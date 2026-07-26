#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseFdListing, parseProcessTable } from '../h037/acquisition-lib.mjs';
import {
  controlIdAt,
  createCompanionClient,
  firstSubscription,
  waitForConnectionStatus,
  waitForEntityDefinitionChoice,
} from '../h034/lib/trpc.mjs';
import { proxyEvents } from '../h034/lib/evidence.mjs';
import { SatelliteObserver } from '../h034/lib/satellite.mjs';
import { command, exactRuntimeText, waitFor } from '../h034/lib/util.mjs';
import {
  parseProcessStatus,
  selectCausalReceipt,
  selectGraphicalSession,
  virtualInvocationAudit,
} from '../h038/physical-lib.mjs';
import { captureHostSnapshot, ownerObservation, waitForStableHostState } from './host-observer.mjs';
import {
  H039_CLAIM_BOUNDARY,
  classifyDeviceTransition,
  classifyPostReconnectOutcome,
  commandsBetween,
  fileDescriptorMatchesDevice,
  logMarkers,
  parseProcStartTicks,
  parseStatIdentity,
  runId as createRunId,
  sameTopLevelLifecycle,
  sha256,
  sha256Canonical,
  validateControlConfiguration,
} from './reconnect-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const H038_DIRECTORY = path.join(REPOSITORY_ROOT, 'lab/h038');
const COMPOSE_FILE = path.join(H038_DIRECTORY, 'compose.yaml');
const CONTROL_ID = 'lower-third.visibility';
const BINDING_ID = 'component.visibility/preview/lower-third';
const BUTTON_LOCATION = Object.freeze({ pageNumber: 1, row: 0, column: 0 });
const COMPANION_PORT = 38038;
const REST_PORT = 33038;
const SATELLITE_PORT = 36628;
const PRODUCT_ENDPOINT = 'ws://172.30.38.10:8081/device';
const SOURCE_FILES = [
  '.overlaykit/governance/changes/CHG-0010.json',
  'lab/h034/Dockerfile.companion',
  'lab/h034/Dockerfile.overlaykit',
  'lab/h034/device-proxy.cjs',
  'lab/h034/install-companion-module.sh',
  'lab/h034/lib/evidence.mjs',
  'lab/h034/lib/proxy-evidence.cjs',
  'lab/h034/lib/satellite.mjs',
  'lab/h034/lib/trpc.mjs',
  'lab/h034/lib/util.mjs',
  'lab/h034/overlaykit-entrypoint.sh',
  'lab/h035/inventory-lib.mjs',
  'lab/h037/acquisition-lib.mjs',
  'lab/h038/companion-entrypoint.sh',
  'lab/h038/compose.yaml',
  'lab/h038/physical-lib.mjs',
  'lab/h039/host-observer.mjs',
  'lab/h039/host-observer.test.mjs',
  'lab/h039/reconnect-lib.mjs',
  'lab/h039/reconnect-lib.test.mjs',
  'lab/h039/run.mjs',
  'lab/h039/schema.test.mjs',
  'lab/h039/schemas/reconnect-run.schema.json',
  'lab/h039/verify.mjs',
  'package.json',
];

function parseArgs(argv) {
  const result = {
    h038: 'artifacts/h038/h038-2026-07-25T21-18-52-919Z-01f784c9/run.json',
    evidenceDirectory: null,
    pressWindowSeconds: 45,
    transitionWindowSeconds: 90,
    reacquisitionWindowSeconds: 30,
    quietSeconds: 5,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--h038') result.h038 = argv[++index] ?? '';
    else if (argument === '--evidence-dir') result.evidenceDirectory = argv[++index] ?? '';
    else if (argument === '--window-seconds') {
      result.pressWindowSeconds = Number(argv[++index]);
    } else if (argument === '--transition-seconds') {
      result.transitionWindowSeconds = Number(argv[++index]);
    } else if (argument === '--reacquisition-seconds') {
      result.reacquisitionWindowSeconds = Number(argv[++index]);
    } else if (argument === '--quiet-seconds') {
      result.quietSeconds = Number(argv[++index]);
    } else {
      throw new Error(`Unknown H-039 argument: ${argument}`);
    }
  }
  if (
    !Number.isSafeInteger(result.pressWindowSeconds) ||
    result.pressWindowSeconds < 10 ||
    result.pressWindowSeconds > 180
  ) {
    throw new Error('H-039 physical press window must be between 10 and 180 seconds');
  }
  if (
    !Number.isSafeInteger(result.transitionWindowSeconds) ||
    result.transitionWindowSeconds < 20 ||
    result.transitionWindowSeconds > 300
  ) {
    throw new Error('H-039 USB transition window must be between 20 and 300 seconds');
  }
  if (
    !Number.isSafeInteger(result.reacquisitionWindowSeconds) ||
    result.reacquisitionWindowSeconds < 5 ||
    result.reacquisitionWindowSeconds > 120
  ) {
    throw new Error('H-039 reacquisition window must be between 5 and 120 seconds');
  }
  if (
    !Number.isSafeInteger(result.quietSeconds) ||
    result.quietSeconds < 2 ||
    result.quietSeconds > 15
  ) {
    throw new Error('H-039 quiet window must be between 2 and 15 seconds');
  }
  return result;
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

function parseOsRelease(text) {
  return Object.fromEntries(
    text
      .split(/\r?\n/u)
      .filter((line) => line.includes('='))
      .map((line) => {
        const separator = line.indexOf('=');
        const key = line.slice(0, separator);
        const raw = line.slice(separator + 1);
        const value =
          raw.length >= 2 &&
          ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'")))
            ? raw.slice(1, -1)
            : raw;
        return [key, value];
      })
  );
}

async function observePrincipal(expectedUser) {
  const [user, uid, primaryGroup, gid, gids, groupNames] = await Promise.all([
    command('id', ['-un', expectedUser]),
    command('id', ['-u', expectedUser]),
    command('id', ['-gn', expectedUser]),
    command('id', ['-g', expectedUser]),
    command('id', ['-G', expectedUser]),
    command('id', ['-Gn', expectedUser]),
  ]);
  const observedGids = gids.stdout.trim().split(/\s+/u).map(Number);
  const observedNames = groupNames.stdout.trim().split(/\s+/u);
  if (
    observedGids.length !== observedNames.length ||
    observedGids.some((value) => !Number.isSafeInteger(value) || value < 0)
  ) {
    throw new Error('H-039 could not bind the current principal group identities');
  }
  const groups = observedGids
    .map((observedGid, index) => ({ gid: observedGid, name: observedNames[index] }))
    .sort((left, right) => left.gid - right.gid);
  const principal = {
    user: user.stdout.trim(),
    uid: Number(uid.stdout.trim()),
    primaryGroup: primaryGroup.stdout.trim(),
    gid: Number(gid.stdout.trim()),
    groups,
  };
  if (
    principal.user !== expectedUser ||
    !Number.isSafeInteger(principal.uid) ||
    !Number.isSafeInteger(principal.gid) ||
    principal.primaryGroup.length === 0
  ) {
    throw new Error('H-039 current principal identity is incomplete');
  }
  return principal;
}

async function observeHostIdentity(expectedUser) {
  const [osReleaseText, kernel, machine, principal] = await Promise.all([
    readFile('/etc/os-release', 'utf8'),
    command('uname', ['-r']),
    command('uname', ['-m']),
    observePrincipal(expectedUser),
  ]);
  const release = parseOsRelease(osReleaseText);
  if (!release.ID || !release.VERSION_ID) {
    throw new Error('H-039 could not identify the current Linux distribution');
  }
  return {
    observedAt: new Date().toISOString(),
    osId: release.ID,
    osVersion: release.VERSION_ID,
    kernel: kernel.stdout.trim(),
    architecture: os.arch(),
    machine: machine.stdout.trim(),
    principal,
  };
}

function sourceHashes() {
  return Object.fromEntries(
    SOURCE_FILES.map((relativePath) => [
      relativePath,
      sha256(readFileSync(path.join(REPOSITORY_ROOT, relativePath))),
    ])
  );
}

function exactNode(snapshot) {
  const matches = snapshot.hidraw.filter((entry) => entry.serialMatches);
  if (snapshot.state !== 'present' || matches.length !== 1 || matches[0].stat === null) {
    throw new Error(`H-039 expected one exact present hidraw node, observed ${snapshot.state}`);
  }
  return matches[0];
}

function validateHistoricalH038(bytes, run) {
  const { evidenceSha256, ...evidence } = run;
  if (
    run.schemaVersion !== 'overlaykit-h038-physical-run/v1' ||
    run.hypothesis !== 'H-038' ||
    sha256Canonical(evidence) !== evidenceSha256 ||
    !run.cleanup?.successful ||
    run.device?.vendorId !== '0fd9' ||
    run.device?.productId !== '0080' ||
    run.invocationAudit?.virtualInvocationCount !== 0
  ) {
    throw new Error('H-039 requires intact successful H-038 physical evidence');
  }
  for (const [relativePath, expected] of Object.entries(run.collector.sourceSha256)) {
    const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
    if (
      !absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`) ||
      sha256(readFileSync(absolutePath)) !== expected
    ) {
      throw new Error(`H-039 detected stale H-038 source: ${relativePath}`);
    }
  }
  return {
    fileSha256: sha256(bytes),
    evidenceSha256,
    historicalManifestContentHash: run.collector.governanceManifestContentHash,
  };
}

async function graphicalSession(principal) {
  const listed = await command('loginctl', ['list-sessions', '--no-legend', '--no-pager']);
  const ids = listed.stdout
    .split(/\r?\n/u)
    .map((line) => line.trim().split(/\s+/u)[0])
    .filter(Boolean);
  const sessions = [];
  for (const id of ids) {
    const observed = await command('loginctl', [
      'show-session',
      id,
      '--property=Id',
      '--property=Name',
      '--property=Active',
      '--property=State',
      '--property=Class',
      '--property=Remote',
      '--property=Type',
      '--property=Seat',
      '--property=TTY',
    ]);
    sessions.push(
      Object.fromEntries(
        observed.stdout
          .split(/\r?\n/u)
          .filter((line) => line.includes('='))
          .map((line) => {
            const separator = line.indexOf('=');
            return [line.slice(0, separator), line.slice(separator + 1)];
          })
      )
    );
  }
  const selected = selectGraphicalSession(sessions, principal);
  if (!selected) throw new Error(`No active local graphical session exists for ${principal}`);
  return { selected, observed: sessions };
}

class OverlayKitApi {
  constructor(audit) {
    this.cookie = '';
    this.audit = audit;
  }

  async request(method, route, body) {
    this.audit.push({ kind: 'overlaykit-http', method, path: route });
    const response = await fetch(`http://127.0.0.1:${REST_PORT}${route}`, {
      method,
      headers: {
        Accept: 'application/json',
        Origin: 'http://h038-maintainer.local',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(this.cookie ? { Cookie: this.cookie } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';', 1)[0];
    const text = await response.text();
    if (!response.ok) throw new Error(`${method} ${route} returned ${response.status}: ${text}`);
    return text ? JSON.parse(text) : null;
  }
}

async function provisionOverlayKit(api) {
  await api.request('POST', '/api/auth/setup', {
    email: 'owner@h039.overlaykit.local',
    displayName: 'H039 Owner',
    password: 'h039-ephemeral-owner-password',
  });
  const show = await api.request('POST', '/api/shows', {
    name: 'H039 Reconnect',
    description: 'Ephemeral governed physical reconnect experiment',
  });
  const showId = show.data.id;
  await api.request('POST', `/api/shows/${showId}/production/preview`, {
    scene: {
      id: 'h039-scene',
      name: 'H039 Scene',
      elements: [
        {
          id: 'lower-third',
          tag: 'section',
          content: 'H039 lower third',
          attributes: { 'aria-label': 'H039 lower third' },
          styles: { display: 'none' },
        },
      ],
    },
    variables: {},
  });
  const trust = await api.request('GET', '/api/integrations/device-trust');
  const issued = await api.request('POST', `/api/shows/${showId}/integrations/device-credentials`, {
    label: 'H039 Companion',
    targets: ['preview'],
    controlIds: [CONTROL_ID],
    scopes: ['feedback:read', 'component.visibility:write'],
    expiresAt: Date.now() + 60 * 60 * 1000,
  });
  return {
    showId,
    credentialId: issued.data.credential.credentialId,
    trustBundle: trust.data.trustBundle,
    bearer: issued.data.token,
  };
}

async function configureCompanion(client, provisioning, audit) {
  const mutate = async (procedure, operation) => {
    audit.push({ kind: 'trpc-configuration', procedure });
    return operation();
  };
  await mutate('userConfig.setConfigKey', () =>
    client.userConfig.setConfigKey.mutate({
      key: 'satellite_subscriptions_enabled',
      value: true,
    })
  );
  const modules = await firstSubscription(client.instances.modules.watch, undefined);
  const moduleInfo = modules?.info?.['connection:overlaykit-server'];
  if (!moduleInfo?.devVersion || moduleInfo.devVersion.versionId !== 'dev') {
    throw new Error('Companion did not load the governed local module');
  }
  const connectionId = await mutate('instances.connections.add', () =>
    client.instances.connections.add.mutate({
      module: { type: 'overlaykit-server' },
      label: 'OverlayKit_H039',
      versionId: 'dev',
    })
  );
  const configError = await mutate('instances.connections.setConfig', () =>
    client.instances.connections.setConfig.mutate({
      connectionId,
      label: 'OverlayKit_H039',
      enabled: true,
      config: {
        endpoint: PRODUCT_ENDPOINT,
        allowInsecureLan: true,
        trustBundle: JSON.stringify(provisioning.trustBundle),
      },
      secrets: { bearer: provisioning.bearer },
      updatePolicy: 'stable',
    })
  );
  if (configError !== null) throw new Error(`Companion rejected H-039 config: ${configError}`);
  await waitForConnectionStatus(
    client,
    connectionId,
    (status) => status?.category === 'good' && status?.level === 'ok',
    30_000
  );
  await Promise.all([
    waitForEntityDefinitionChoice(
      client.instances.definitions.actions,
      connectionId,
      'visibility.toggle',
      'binding',
      BINDING_ID
    ),
    waitForEntityDefinitionChoice(
      client.instances.definitions.feedbacks,
      connectionId,
      'visibility.state',
      'binding',
      BINDING_ID
    ),
  ]);
  await mutate('controls.resetControl', () =>
    client.controls.resetControl.mutate({ location: BUTTON_LOCATION, newType: 'button' })
  );
  const controlId = await waitFor(() => controlIdAt(client, BUTTON_LOCATION), {
    timeoutMs: 10_000,
    message: 'Companion did not create the top-left H-039 button',
  });
  const control = await firstSubscription(
    client.controls.watchControl,
    { controlId },
    (update) => update?.type === 'init' && typeof update.runtime?.current_step_id === 'string'
  );
  const entityLocation = { stepId: control.runtime.current_step_id, setId: 'down' };
  const actionId = await mutate('controls.entities.add:action', () =>
    client.controls.entities.add.mutate({
      controlId,
      entityLocation,
      ownerId: null,
      connectionId,
      entityType: 'action',
      entityDefinition: 'visibility.toggle',
    })
  );
  const actionConfigured = await mutate('controls.entities.setOption:action', () =>
    client.controls.entities.setOption.mutate({
      controlId,
      entityLocation,
      entityId: actionId,
      key: 'binding',
      value: { isExpression: false, value: BINDING_ID },
    })
  );
  const feedbackId = await mutate('controls.entities.add:feedback', () =>
    client.controls.entities.add.mutate({
      controlId,
      entityLocation: 'feedbacks',
      ownerId: null,
      connectionId,
      entityType: 'feedback',
      entityDefinition: 'visibility.state',
    })
  );
  const feedbackConfigured = await mutate('controls.entities.setOption:feedback', () =>
    client.controls.entities.setOption.mutate({
      controlId,
      entityLocation: 'feedbacks',
      entityId: feedbackId,
      key: 'binding',
      value: { isExpression: false, value: BINDING_ID },
    })
  );
  if (!actionId || actionConfigured !== true || !feedbackId || feedbackConfigured !== true) {
    throw new Error('Companion did not configure the H-039 toggle button');
  }
  return {
    connectionId,
    controlId,
    moduleVersionId: moduleInfo.devVersion.versionId,
    actionId,
    feedbackId,
  };
}

async function serviceLifecycle(compose, service) {
  const runningId = (await compose('ps', '--quiet', service)).stdout.trim();
  const anyId = runningId || (await compose('ps', '--quiet', '--all', service)).stdout.trim();
  if (!anyId) {
    return {
      observed: true,
      present: false,
      running: false,
      containerId: null,
      startedAt: null,
      restartCount: null,
      pid1StartTicks: null,
      imageId: null,
    };
  }
  const inspected = JSON.parse((await command('docker', ['inspect', anyId])).stdout)[0];
  let pid1StartTicks = null;
  if (inspected.State.Running) {
    try {
      const procStat = await command('docker', ['exec', anyId, 'cat', '/proc/1/stat']);
      pid1StartTicks = parseProcStartTicks(procStat.stdout.trim());
    } catch {
      pid1StartTicks = null;
    }
  }
  return {
    observed: true,
    present: true,
    running: inspected.State.Running,
    containerId: anyId,
    startedAt: inspected.State.StartedAt,
    restartCount: inspected.RestartCount,
    pid1StartTicks,
    imageId: inspected.Image,
  };
}

async function fileDescriptorReceipts(containerId, surface) {
  const listing = await command('docker', [
    'exec',
    '--user',
    String(surface.uid),
    containerId,
    'ls',
    '-l',
    `/proc/${surface.pid}/fd`,
  ]);
  const descriptors = parseFdListing(listing.stdout);
  return Promise.all(
    descriptors.map(async (descriptor) => {
      if (!descriptor.target.startsWith('/dev/hidraw')) return descriptor;
      try {
        const observed = await command('docker', [
          'exec',
          '--user',
          String(surface.uid),
          containerId,
          'stat',
          '-Lc',
          '%t:%T|%i|%F',
          `/proc/${surface.pid}/fd/${descriptor.descriptor}`,
        ]);
        const fdinfo = await command('docker', [
          'exec',
          '--user',
          String(surface.uid),
          containerId,
          'cat',
          `/proc/${surface.pid}/fdinfo/${descriptor.descriptor}`,
        ]);
        return {
          ...descriptor,
          stat: parseStatIdentity(observed.stdout.trim()),
          fdinfoSha256: sha256(fdinfo.stdout),
        };
      } catch (error) {
        return {
          ...descriptor,
          stat: null,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    })
  );
}

async function surfaceProcesses(containerLifecycle) {
  if (!containerLifecycle.running) return [];
  const containerId = containerLifecycle.containerId;
  const table = parseProcessTable(
    (
      await command('docker', [
        'exec',
        containerId,
        'ps',
        '-eo',
        'pid=,ppid=,uid=,gid=,comm=,args=',
      ])
    ).stdout
  );
  const surfaces = table.filter((entry) => entry.args?.includes('SurfaceThread.js'));
  return Promise.all(
    surfaces.map(async (surface) => {
      const [status, procStat, fileDescriptors] = await Promise.all([
        command('docker', [
          'exec',
          '--user',
          String(surface.uid),
          containerId,
          'cat',
          `/proc/${surface.pid}/status`,
        ]),
        command('docker', [
          'exec',
          '--user',
          String(surface.uid),
          containerId,
          'cat',
          `/proc/${surface.pid}/stat`,
        ]),
        fileDescriptorReceipts(containerId, surface),
      ]);
      return {
        ...surface,
        ...parseProcessStatus(status.stdout),
        startTicks: parseProcStartTicks(procStat.stdout.trim()),
        fileDescriptors,
      };
    })
  );
}

async function captureRuntime(
  compose,
  stage,
  hostNode,
  knownDevicePaths,
  serial,
  bearer,
  evidenceDirectory
) {
  const [overlaykit, companion] = await Promise.all([
    serviceLifecycle(compose, 'overlaykit'),
    serviceLifecycle(compose, 'companion'),
  ]);
  const logs = (await compose('logs', '--no-color', '--timestamps', 'companion')).stdout;
  if (logs.includes(bearer)) throw new Error('Companion logs exposed the ephemeral bearer');
  const logName = `${stage}-companion.log`;
  await writeFile(path.join(evidenceDirectory, logName), logs, { mode: 0o600 });
  const surfaces = await surfaceProcesses(companion);
  const snapshot = {
    capturedAt: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    lifecycle: { overlaykit, companion },
    surfaceProcesses: surfaces,
    logArtifact: { path: logName, sha256: sha256(logs) },
    logMarkers: logMarkers(logs, serial, [
      ...new Set([hostNode?.devicePath, ...knownDevicePaths].filter(Boolean)),
    ]),
  };
  return {
    ...snapshot,
    matchesCurrentDevice: hostNode ? fileDescriptorMatchesDevice(snapshot, hostNode) : false,
  };
}

async function captureRuntimeIdentities(compose, evidenceDirectory, lockedInputs) {
  const companionPath = path.join(evidenceDirectory, 'companion-runtime.txt');
  const overlaykitPath = path.join(evidenceDirectory, 'overlaykit-runtime.txt');
  const companionBytes = await readFile(companionPath);
  const overlaykitBytes = await readFile(overlaykitPath);
  const companion = exactRuntimeText(companionBytes.toString('utf8'));
  const overlaykit = exactRuntimeText(overlaykitBytes.toString('utf8'));
  if (
    companion.node !== 'v22.22.2' ||
    companion.os !== 'ubuntu' ||
    companion.version !== '24.04' ||
    !/^[0-9a-f]{64}$/u.test(companion.module_sha256 ?? '') ||
    overlaykit.node !== 'v24.6.0' ||
    overlaykit.commit !== lockedInputs.overlaykit.commit ||
    overlaykit.os !== 'ubuntu' ||
    overlaykit.version !== '24.04'
  ) {
    throw new Error('H-039 runtime identities do not match the locked H-038 inputs');
  }
  const companionContainerId = (await compose('ps', '--quiet', 'companion')).stdout.trim();
  const modulePath = path.join(evidenceDirectory, 'overlaykit-server-0.1.0.tgz');
  await command('docker', [
    'cp',
    `${companionContainerId}:/opt/h034/overlaykit-server-0.1.0.tgz`,
    modulePath,
  ]);
  await chmod(modulePath, 0o600);
  const moduleBytes = await readFile(modulePath);
  if (sha256(moduleBytes) !== companion.module_sha256) {
    throw new Error('H-039 runtime module archive does not match its in-image digest');
  }
  return {
    companion: {
      values: companion,
      receipt: { path: 'companion-runtime.txt', sha256: sha256(companionBytes) },
      moduleArchive: {
        path: 'overlaykit-server-0.1.0.tgz',
        sha256: sha256(moduleBytes),
      },
    },
    overlaykit: {
      values: overlaykit,
      receipt: { path: 'overlaykit-runtime.txt', sha256: sha256(overlaykitBytes) },
    },
  };
}

function pressWindow(stage, challenge, timeoutSeconds, instruction) {
  return {
    stage,
    challenge,
    openedAt: new Date().toISOString(),
    openedMonotonicNs: process.hrtime.bigint().toString(),
    timeoutSeconds,
    instruction,
  };
}

function settledSummary(result) {
  if (result.status === 'fulfilled') return { status: 'fulfilled', error: null };
  return {
    status: 'rejected',
    error: result.reason instanceof Error ? result.reason.message : String(result.reason),
  };
}

async function satellitePressCycle(satellite, subId, expectedText, afterNs, timeoutMs) {
  const pressed = await satellite.waitFor(
    (line) =>
      line.command === 'SUB-STATE' &&
      line.values.SUBID === subId &&
      line.values.TEXT === expectedText &&
      line.values.PRESSED === '1' &&
      BigInt(line.monotonicNs) > BigInt(afterNs),
    timeoutMs
  );
  const released = await satellite.waitFor(
    (line) =>
      line.command === 'SUB-STATE' &&
      line.values.SUBID === subId &&
      line.values.TEXT === expectedText &&
      line.values.PRESSED === '0' &&
      BigInt(line.monotonicNs) > BigInt(pressed.monotonicNs),
    timeoutMs
  );
  return { pressed, released };
}

async function executePhysicalWindow({
  stage,
  challenge,
  timeoutSeconds,
  instruction,
  expectedValue,
  expectedText,
  afterEventSequence,
  evidenceDirectory,
  satellite,
  subId,
}) {
  const window = pressWindow(stage, challenge, timeoutSeconds, instruction);
  process.stdout.write(`H-039 ${challenge}: ${instruction} (${timeoutSeconds}s).\n`);
  const results = await Promise.allSettled([
    waitFor(
      async () => {
        try {
          return selectCausalReceipt(await proxyEvents(evidenceDirectory), {
            afterEventSequence,
            controlId: CONTROL_ID,
            expectedValue,
          });
        } catch {
          return null;
        }
      },
      {
        timeoutMs: timeoutSeconds * 1000,
        intervalMs: 50,
        message: `No ${stage} physical command reached authoritative OverlayKit state`,
      }
    ),
    satellitePressCycle(
      satellite,
      subId,
      expectedText,
      window.openedMonotonicNs,
      timeoutSeconds * 1000
    ),
  ]);
  const closedAt = new Date().toISOString();
  const closedMonotonicNs = process.hrtime.bigint().toString();
  return {
    window: { ...window, closedAt, closedMonotonicNs },
    waitResults: {
      causal: settledSummary(results[0]),
      satellite: settledSummary(results[1]),
    },
    causalReceipt: results[0].status === 'fulfilled' ? results[0].value : null,
    pressCycle: results[1].status === 'fulfilled' ? results[1].value : null,
    passed: results.every((result) => result.status === 'fulfilled'),
  };
}

function selectedConnectionInfo(info) {
  if (info === null || typeof info !== 'object' || Array.isArray(info)) return null;
  return {
    id: info.id,
    label: info.label,
    moduleType: info.moduleType,
    moduleId: info.moduleId,
    moduleVersionId: info.moduleVersionId,
    updatePolicy: info.updatePolicy,
    enabled: info.enabled,
    sortOrder: info.sortOrder,
    collectionId: info.collectionId,
  };
}

async function captureConfigurationReceipt(client, configured) {
  const firstControlId = await controlIdAt(client, BUTTON_LOCATION);
  const [control, connectionUpdates, connectionEdit] = await Promise.all([
    firstControlId === null
      ? null
      : firstSubscription(
          client.controls.watchControl,
          { controlId: firstControlId },
          (update) => update?.type === 'init'
        ),
    firstSubscription(
      client.instances.connections.watch,
      undefined,
      (updates) => Array.isArray(updates) && updates.some((update) => update?.type === 'init')
    ),
    client.instances.connections.edit.query({ connectionId: configured.connectionId }),
  ]);
  const secondControlId = await controlIdAt(client, BUTTON_LOCATION);
  if (firstControlId !== secondControlId) {
    throw new Error('Companion control location changed during the configuration observation');
  }
  const connectionInit = connectionUpdates.find((update) => update?.type === 'init');
  const connectionInfo = selectedConnectionInfo(
    connectionInit?.info?.[configured.connectionId] ?? null
  );
  const bearer = connectionEdit?.secrets?.bearer;
  const connection =
    connectionInfo && connectionEdit
      ? {
          ...connectionInfo,
          config: connectionEdit.config,
          secretKeys: Object.keys(connectionEdit.secrets ?? {}).sort(),
          bearerSha256: typeof bearer === 'string' ? sha256(bearer) : null,
        }
      : null;
  return {
    location: BUTTON_LOCATION,
    controlId: firstControlId,
    actionId: configured.actionId,
    feedbackId: configured.feedbackId,
    controlConfig: control?.config ?? null,
    connection,
  };
}

function validExpectedConfiguration(configuration, expectedBearerSha256) {
  const connection = configuration.connection;
  return (
    configuration.controlId !== null &&
    connection !== null &&
    typeof connection.id === 'string' &&
    connection.id.length > 0 &&
    connection.moduleType === 'connection' &&
    connection.moduleId === 'overlaykit-server' &&
    connection.moduleVersionId === 'dev' &&
    connection.updatePolicy === 'stable' &&
    connection.enabled === true &&
    connection.config?.endpoint === PRODUCT_ENDPOINT &&
    connection.config?.allowInsecureLan === true &&
    typeof connection.config?.trustBundle === 'string' &&
    connection.config.trustBundle.length > 0 &&
    connection.bearerSha256 === expectedBearerSha256 &&
    Array.isArray(connection.secretKeys) &&
    JSON.stringify(connection.secretKeys) === JSON.stringify(['bearer']) &&
    validateControlConfiguration(configuration.controlConfig, {
      connectionId: connection.id,
      actionId: configuration.actionId,
      feedbackId: configuration.feedbackId,
      binding: BINDING_ID,
    })
  );
}

async function configurationContinuity(client, configured, freeze, audit, expectedBearerSha256) {
  try {
    const current = await captureConfigurationReceipt(client, configured);
    const currentSha256 = sha256Canonical(current);
    return {
      observed: true,
      current,
      currentSha256,
      auditEntryCount: audit.length,
      expectedConfigurationValid: validExpectedConfiguration(current, expectedBearerSha256),
      unchanged:
        current.controlId === configured.controlId &&
        validExpectedConfiguration(current, expectedBearerSha256) &&
        currentSha256 === freeze.configurationSha256 &&
        audit.length === freeze.auditEntryCount,
      error: null,
    };
  } catch (error) {
    return {
      observed: false,
      current: null,
      currentSha256: null,
      auditEntryCount: audit.length,
      expectedConfigurationValid: false,
      unchanged: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

const arguments_ = parseArgs(process.argv.slice(2));
const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
if (nodeMajor !== 22 || nodeMinor < 20) {
  throw new Error('H-039 requires Node >=22.20 and <23');
}
const id = createRunId();
const evidenceDirectory = path.resolve(
  REPOSITORY_ROOT,
  arguments_.evidenceDirectory ?? path.join('artifacts/h039', id)
);
await mkdir(evidenceDirectory, { recursive: true });
const h038Path = path.resolve(REPOSITORY_ROOT, arguments_.h038);
const h038Bytes = await readFile(h038Path);
const h038 = JSON.parse(h038Bytes);
const h038Receipt = validateHistoricalH038(h038Bytes, h038);
const serial = h038.device.serial;
const observedHost = await observeHostIdentity(h038.host.principal.user);
const principal = observedHost.principal;
if (
  observedHost.osId !== 'fedora' ||
  observedHost.osVersion !== h038.host.osVersion ||
  observedHost.kernel !== h038.host.kernel ||
  observedHost.architecture !== h038.host.architecture ||
  sha256Canonical(principal) !== sha256Canonical(h038.host.principal)
) {
  throw new Error('H-039 current host or principal identity differs from the bounded H-038 host');
}
const session = await graphicalSession(principal.user);
const hostTimeline = [];
const initialStable = await waitForStableHostState('present', serial, {
  timeoutMs: 10_000,
  previousDevicePath: h038.device.devicePath,
  timeline: hostTimeline,
});
const beforeHost = initialStable.snapshot;
const beforeNode = exactNode(beforeHost);
if (beforeNode.stat.gid !== h038.device.gid || !beforeNode.owner?.observed) {
  throw new Error('H-039 current host group or ownership observation differs from H-038');
}
if (beforeNode.owner.pids.length > 0) {
  throw new Error('H-039 requires the exact MK.2 to be initially unowned');
}

const governanceVerify = await command('npm', ['run', 'governance:verify'], {
  cwd: REPOSITORY_ROOT,
});
const governanceVerifyText = `${governanceVerify.stdout}${governanceVerify.stderr}`;
const manifestBytes = await readFile(
  path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
);
const manifest = JSON.parse(manifestBytes);
const initialSourceSha256 = sourceHashes();
if (
  manifest.changes?.['CHG-0010'] !==
  initialSourceSha256['.overlaykit/governance/changes/CHG-0010.json']
) {
  throw new Error('H-039 change contract is not bound by the verified manifest');
}
await writeFile(path.join(evidenceDirectory, 'governance-manifest.json'), manifestBytes, {
  mode: 0o600,
});
await writeFile(path.join(evidenceDirectory, 'governance-verify.txt'), governanceVerifyText, {
  mode: 0o600,
});

const composeProject = `h039${sha256(id).slice(0, 10)}`;
const composeEnvironment = {
  H034_HOST_GID: String(principal.gid),
  H034_HOST_UID: String(principal.uid),
  H034_OVERLAYKIT_ARCHIVE_SHA256: h038.inputs.lockedInputs.overlaykit.archiveSha256,
  H034_OVERLAYKIT_COMMIT: h038.inputs.lockedInputs.overlaykit.commit,
  H038_COMPANION_PORT: String(COMPANION_PORT),
  H038_DEVICE_GID: String(beforeNode.stat.gid),
  H038_DEVICE_PATH: beforeNode.devicePath,
  H038_EVIDENCE_DIR: evidenceDirectory,
  H038_LAB_DIR: H038_DIRECTORY,
  H038_REST_PORT: String(REST_PORT),
  H038_SATELLITE_PORT: String(SATELLITE_PORT),
};
const composeArgs = ['compose', '-p', composeProject, '-f', COMPOSE_FILE];
const compose = (...args) =>
  command('docker', [...composeArgs, ...args], {
    cwd: REPOSITORY_ROOT,
    env: composeEnvironment,
  });
const invocationEntries = [];
const startedAt = new Date().toISOString();
let trpc = null;
let satellite = null;
let provisioning = null;
let run = null;
let primaryError = null;
let cleanup = null;

try {
  await command('docker', [...composeArgs, 'build', 'overlaykit', 'companion'], {
    cwd: REPOSITORY_ROOT,
    env: composeEnvironment,
    inherit: true,
  });
  await compose('up', '--detach', '--wait', '--no-build');
  const runtimeIdentities = await captureRuntimeIdentities(
    compose,
    evidenceDirectory,
    h038.inputs.lockedInputs
  );
  provisioning = await provisionOverlayKit(new OverlayKitApi(invocationEntries));
  trpc = createCompanionClient(`ws://127.0.0.1:${COMPANION_PORT}/trpc`);
  const configured = await configureCompanion(trpc.client, provisioning, invocationEntries);
  const expectedBearerSha256 = sha256(provisioning.bearer);
  const configuration = await captureConfigurationReceipt(trpc.client, configured);
  if (
    configuration.controlId !== configured.controlId ||
    configuration.connection?.id !== configured.connectionId ||
    !validExpectedConfiguration(configuration, expectedBearerSha256)
  ) {
    throw new Error('Companion did not expose the exact configured H-039 control and connection');
  }
  const configurationFreeze = {
    configuration,
    configurationSha256: sha256Canonical(configuration),
    auditEntryCount: invocationEntries.length,
    frozenAt: new Date().toISOString(),
    frozenMonotonicNs: process.hrtime.bigint().toString(),
  };
  satellite = new SatelliteObserver(SATELLITE_PORT);
  await satellite.connect();
  const satelliteId = 'h039-physical';
  await satellite.subscribe(satelliteId, '1/0/0');
  await satellite.waitForState(satelliteId, 'INACTIVE', 20_000);

  const hostBeforeDisconnect = captureHostSnapshot(serial, {
    includeOwners: true,
    previousDevicePath: beforeNode.devicePath,
  });
  const initialNode = exactNode(hostBeforeDisconnect);
  const runtimeBefore = await captureRuntime(
    compose,
    'before',
    initialNode,
    [initialNode.devicePath],
    serial,
    provisioning.bearer,
    evidenceDirectory
  );
  if (
    !runtimeBefore.matchesCurrentDevice ||
    runtimeBefore.logMarkers.ready < 1 ||
    !sameTopLevelLifecycle(runtimeBefore.lifecycle, runtimeBefore.lifecycle)
  ) {
    throw new Error('Initial SurfaceThread FD does not match the current host rdev');
  }
  const eventsBeforeBaseline = await proxyEvents(evidenceDirectory);
  const baselineBoundary = eventsBeforeBaseline.at(-1)?.eventSequence ?? 0;
  const baselineChallenge = sha256(`${id}:${serial}:baseline:${baselineBoundary}`).slice(0, 12);
  const baseline = await executePhysicalWindow({
    stage: 'baseline',
    challenge: baselineChallenge,
    timeoutSeconds: arguments_.pressWindowSeconds,
    instruction: 'PULSA UNA VEZ la tecla superior izquierda antes de desconectar',
    expectedValue: 'active',
    expectedText: 'ACTIVE',
    afterEventSequence: baselineBoundary,
    evidenceDirectory,
    satellite,
    subId: satelliteId,
  });
  if (!baseline.passed) {
    throw new Error(
      `H-039 baseline physical control is inconclusive: ${JSON.stringify(baseline.waitResults)}`
    );
  }

  const afterBaselineSequence = baseline.causalReceipt.acknowledgement.eventSequence;
  const disconnectChallenge = sha256(`${id}:${serial}:disconnect:${afterBaselineSequence}`).slice(
    0,
    12
  );
  const disconnectWindow = pressWindow(
    'disconnect',
    disconnectChallenge,
    arguments_.transitionWindowSeconds,
    'DESCONECTA físicamente el cable USB del Stream Deck MK.2'
  );
  process.stdout.write(
    `H-039 ${disconnectChallenge}: ${disconnectWindow.instruction} (${arguments_.transitionWindowSeconds}s).\n`
  );
  const disconnectedStable = await waitForStableHostState('absent', serial, {
    timeoutMs: arguments_.transitionWindowSeconds * 1000,
    previousDevicePath: initialNode.devicePath,
    timeline: hostTimeline,
  });
  const disconnected = disconnectedStable.snapshot;
  disconnectWindow.closedAt = new Date().toISOString();
  disconnectWindow.closedMonotonicNs = process.hrtime.bigint().toString();
  const runtimeDisconnected = await captureRuntime(
    compose,
    'disconnected',
    null,
    [initialNode.devicePath],
    serial,
    provisioning.bearer,
    evidenceDirectory
  );

  const reconnectChallenge = sha256(
    `${id}:${serial}:reconnect:${disconnectWindow.closedMonotonicNs}`
  ).slice(0, 12);
  const reconnectWindow = pressWindow(
    'reconnect',
    reconnectChallenge,
    arguments_.transitionWindowSeconds,
    'RECONECTA físicamente el cable USB del mismo Stream Deck MK.2'
  );
  process.stdout.write(
    `H-039 ${reconnectChallenge}: ${reconnectWindow.instruction} (${arguments_.transitionWindowSeconds}s).\n`
  );
  const reconnectedStable = await waitForStableHostState('present', serial, {
    timeoutMs: arguments_.transitionWindowSeconds * 1000,
    previousDevicePath: initialNode.devicePath,
    timeline: hostTimeline,
  });
  const reconnected = reconnectedStable.snapshot;
  const reconnectedNode = exactNode(reconnected);
  reconnectWindow.closedAt = new Date().toISOString();
  reconnectWindow.closedMonotonicNs = process.hrtime.bigint().toString();
  const runtimeReconnected = await captureRuntime(
    compose,
    'reconnected',
    reconnectedNode,
    [initialNode.devicePath, reconnectedNode.devicePath],
    serial,
    provisioning.bearer,
    evidenceDirectory
  );

  const reacquisitionStartedAt = new Date().toISOString();
  const reacquisitionStartedNs = process.hrtime.bigint().toString();
  let runtimeReacquisition = runtimeReconnected;
  let reacquired = runtimeReconnected.matchesCurrentDevice;
  let reacquisitionTimeout = null;
  const topLevelAtReturn = sameTopLevelLifecycle(
    runtimeBefore.lifecycle,
    runtimeReconnected.lifecycle
  );
  if (!reacquired && topLevelAtReturn) {
    try {
      runtimeReacquisition = await waitFor(
        async () => {
          runtimeReacquisition = await captureRuntime(
            compose,
            'reacquisition-probe',
            reconnectedNode,
            [initialNode.devicePath, reconnectedNode.devicePath],
            serial,
            provisioning.bearer,
            evidenceDirectory
          );
          return runtimeReacquisition.matchesCurrentDevice ? runtimeReacquisition : null;
        },
        {
          timeoutMs: arguments_.reacquisitionWindowSeconds * 1000,
          intervalMs: 500,
          message: 'Companion did not expose a current-device FD before the H-039 deadline',
        }
      );
      reacquired = true;
    } catch (error) {
      if (error?.cause) throw error;
      reacquisitionTimeout = error instanceof Error ? error.message : String(error);
    }
  } else if (!reacquired) {
    reacquisitionTimeout =
      'Current-device observation was not attempted because the top-level lifecycle changed.';
  }
  const reacquisition = {
    startedAt: reacquisitionStartedAt,
    startedMonotonicNs: reacquisitionStartedNs,
    completedAt: new Date().toISOString(),
    completedMonotonicNs: process.hrtime.bigint().toString(),
    timeoutSeconds: arguments_.reacquisitionWindowSeconds,
    currentDeviceDescriptorObserved: reacquired,
    timeout: reacquisitionTimeout,
    runtime: runtimeReacquisition,
  };

  await new Promise((resolve) => setTimeout(resolve, arguments_.quietSeconds * 1000));
  const eventsBeforePostPress = await proxyEvents(evidenceDirectory);
  const quietUpperSequence = eventsBeforePostPress.at(-1)?.eventSequence ?? afterBaselineSequence;
  const ghostCommands = commandsBetween(
    eventsBeforePostPress,
    afterBaselineSequence,
    quietUpperSequence
  );
  const quietAudit = {
    openedAt: disconnectWindow.openedAt,
    openedMonotonicNs: disconnectWindow.openedMonotonicNs,
    closedAt: new Date().toISOString(),
    closedMonotonicNs: process.hrtime.bigint().toString(),
    afterEventSequence: afterBaselineSequence,
    throughEventSequence: quietUpperSequence,
    quietSecondsAfterReconnect: arguments_.quietSeconds,
    commands: ghostCommands,
    commandCount: ghostCommands.length,
    passed: ghostCommands.length === 0,
  };
  if (!quietAudit.passed) {
    throw new Error('H-039 observed an unprompted command during disconnect/reconnect');
  }

  const lifecycleAfterReconnect = sameTopLevelLifecycle(
    runtimeBefore.lifecycle,
    runtimeReacquisition.lifecycle
  );
  const configurationAfterReconnect = lifecycleAfterReconnect
    ? await configurationContinuity(
        trpc.client,
        configured,
        configurationFreeze,
        invocationEntries,
        expectedBearerSha256
      )
    : {
        observed: false,
        current: null,
        currentSha256: null,
        auditEntryCount: invocationEntries.length,
        expectedConfigurationValid: false,
        unchanged: false,
        error: 'not observed because the top-level lifecycle changed',
      };
  if (lifecycleAfterReconnect && !configurationAfterReconnect.observed) {
    throw new Error('H-039 could not observe Companion configuration continuity');
  }
  let postReconnect = {
    window: null,
    waitResults: null,
    causalReceipt: null,
    pressCycle: null,
    passed: false,
  };
  let outcome;
  if (!lifecycleAfterReconnect) {
    outcome = {
      status: 'refuted',
      stage: 'top-level-lifecycle',
      reason:
        'A top-level Companion or OverlayKit container/process identity changed after hotplug.',
    };
  } else if (!configurationAfterReconnect.unchanged) {
    outcome = {
      status: 'refuted',
      stage: 'configuration-continuity',
      reason:
        'The configured Companion control identity was not observable unchanged after hotplug.',
    };
  } else if (!reacquisition.currentDeviceDescriptorObserved) {
    outcome = {
      status: 'refuted',
      stage: 'companion-reacquisition',
      reason:
        'The exact MK.2 returned at the host, but Companion exposed no descriptor matching its current device number before the declared deadline.',
    };
  } else {
    const postChallenge = sha256(`${id}:${serial}:post-reconnect:${quietUpperSequence}`).slice(
      0,
      12
    );
    postReconnect = await executePhysicalWindow({
      stage: 'post-reconnect',
      challenge: postChallenge,
      timeoutSeconds: arguments_.pressWindowSeconds,
      instruction: 'PULSA UNA VEZ la misma tecla superior izquierda después de reconectar',
      expectedValue: 'inactive',
      expectedText: 'INACTIVE',
      afterEventSequence: quietUpperSequence,
      evidenceDirectory,
      satellite,
      subId: satelliteId,
    });
    const postClassification = classifyPostReconnectOutcome(
      postReconnect.waitResults.satellite,
      postReconnect.waitResults.causal
    );
    if (postClassification === 'inconclusive') {
      throw new Error(
        `H-039 post-reconnect observation is inconclusive and cannot refute recovery: ${JSON.stringify(postReconnect.waitResults)}`
      );
    }
    outcome =
      postClassification === 'supported'
        ? {
            status: 'supported',
            stage: 'complete',
            reason:
              'The unchanged post-login stack delivered a second physical press to acknowledged authoritative state after exact disconnect/reconnect.',
          }
        : {
            status: 'refuted',
            stage: 'post-reconnect-physical-input',
            reason:
              'Satellite observed the challenged physical press/release, but no bounded causally acknowledged authoritative chain completed.',
          };
  }

  const runtimeFinal = await captureRuntime(
    compose,
    'final',
    reconnectedNode,
    [initialNode.devicePath, reconnectedNode.devicePath],
    serial,
    provisioning.bearer,
    evidenceDirectory
  );
  const lifecycleFinal = sameTopLevelLifecycle(runtimeBefore.lifecycle, runtimeFinal.lifecycle);
  const configurationFinal = lifecycleFinal
    ? await configurationContinuity(
        trpc.client,
        configured,
        configurationFreeze,
        invocationEntries,
        expectedBearerSha256
      )
    : {
        observed: false,
        current: null,
        currentSha256: null,
        auditEntryCount: invocationEntries.length,
        expectedConfigurationValid: false,
        unchanged: false,
        error: 'not observed because the top-level lifecycle changed',
      };
  if (
    outcome.stage !== 'top-level-lifecycle' &&
    outcome.stage !== 'configuration-continuity' &&
    (!configurationFinal.observed || !configurationFinal.unchanged)
  ) {
    throw new Error('H-039 final configuration continuity could not be established');
  }
  const audit = virtualInvocationAudit(invocationEntries);
  if (!audit.passed) throw new Error('H-039 invoked a forbidden virtual-press path');
  if (outcome.status === 'supported') {
    if (!runtimeFinal.matchesCurrentDevice || !configurationFinal.unchanged || !lifecycleFinal) {
      throw new Error(
        'H-039 physical success lacks current-FD, configuration, or lifecycle evidence'
      );
    }
  }

  const timelineText = `${hostTimeline.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
  await writeFile(path.join(evidenceDirectory, 'host-poll.jsonl'), timelineText, {
    mode: 0o600,
  });
  const finalSourceSha256 = sourceHashes();
  if (JSON.stringify(initialSourceSha256) !== JSON.stringify(finalSourceSha256)) {
    throw new Error('H-039 source changed during the physical experiment');
  }
  run = {
    schemaVersion: 'overlaykit-h039-reconnect-run/v1',
    hypothesis: 'H-039',
    runId: id,
    startedAt,
    completedAt: new Date().toISOString(),
    outcome,
    collector: {
      node: process.version,
      commit: (await command('git', ['rev-parse', 'HEAD'], { cwd: REPOSITORY_ROOT })).stdout.trim(),
      sourceSha256: finalSourceSha256,
      sourceStable: true,
      governance: {
        manifestSnapshotPath: 'governance-manifest.json',
        manifestFileSha256: sha256(manifestBytes),
        manifestContentHash: manifest.contentHash,
        changeSha256: manifest.changes['CHG-0010'],
        verifyReceiptPath: 'governance-verify.txt',
        verifyReceiptSha256: sha256(governanceVerifyText),
        planHash: manifest.planHash,
      },
    },
    inputs: {
      h038Path: path.relative(REPOSITORY_ROOT, h038Path),
      h038FileSha256: h038Receipt.fileSha256,
      h038EvidenceSha256: h038Receipt.evidenceSha256,
      h038HistoricalManifestContentHash: h038Receipt.historicalManifestContentHash,
      lockedInputs: h038.inputs.lockedInputs,
    },
    host: {
      observedAt: observedHost.observedAt,
      osId: observedHost.osId,
      osVersion: observedHost.osVersion,
      kernel: observedHost.kernel,
      architecture: observedHost.architecture,
      machine: observedHost.machine,
      principal,
      graphicalSession: session.selected,
    },
    runtimeIdentities,
    device: {
      vendorId: h038.device.vendorId,
      productId: h038.device.productId,
      model: h038.device.model,
      serial,
      initialGid: h038.device.gid,
      transition: classifyDeviceTransition(initialNode, reconnectedNode),
    },
    configuration: {
      freeze: configurationFreeze,
      afterReconnect: configurationAfterReconnect,
      final: configurationFinal,
    },
    lifecycle: {
      before: runtimeBefore.lifecycle,
      afterReconnect: runtimeReacquisition.lifecycle,
      final: runtimeFinal.lifecycle,
      unchangedAfterReconnect: lifecycleAfterReconnect,
      unchangedFinal: lifecycleFinal,
      automaticSurfaceLifecycle: {
        before: runtimeBefore.surfaceProcesses.map(({ pid, startTicks }) => ({ pid, startTicks })),
        disconnected: runtimeDisconnected.surfaceProcesses.map(({ pid, startTicks }) => ({
          pid,
          startTicks,
        })),
        reconnected: runtimeReconnected.surfaceProcesses.map(({ pid, startTicks }) => ({
          pid,
          startTicks,
        })),
        reacquisition: runtimeReacquisition.surfaceProcesses.map(({ pid, startTicks }) => ({
          pid,
          startTicks,
        })),
        final: runtimeFinal.surfaceProcesses.map(({ pid, startTicks }) => ({ pid, startTicks })),
      },
    },
    observations: {
      initial: hostBeforeDisconnect,
      disconnected,
      reconnected,
      runtimeBefore,
      runtimeDisconnected,
      runtimeReconnected,
      reacquisition,
      runtimeFinal,
      hostPollArtifact: { path: 'host-poll.jsonl', sha256: sha256(timelineText) },
    },
    windows: {
      baseline: baseline.window,
      disconnect: disconnectWindow,
      reconnect: reconnectWindow,
      postReconnect: postReconnect.window,
    },
    baseline: {
      waitResults: baseline.waitResults,
      causalReceipt: baseline.causalReceipt,
      pressCycle: baseline.pressCycle,
      passed: baseline.passed,
    },
    quietAudit,
    postReconnect: {
      waitResults: postReconnect.waitResults,
      causalReceipt: postReconnect.causalReceipt,
      pressCycle: postReconnect.pressCycle,
      passed: postReconnect.passed,
    },
    invocationAudit: audit,
    provisioning: {
      showId: provisioning.showId,
      credentialId: provisioning.credentialId,
      bearerSha256: sha256(provisioning.bearer),
      ephemeral: true,
    },
    claimBoundary: H039_CLAIM_BOUNDARY,
  };
} catch (error) {
  primaryError = error;
  try {
    const diagnostics = await compose('logs', '--no-color', '--timestamps');
    await writeFile(
      path.join(evidenceDirectory, 'compose-logs.txt'),
      `${diagnostics.stdout}${diagnostics.stderr}`,
      { mode: 0o600 }
    );
  } catch {
    // The primary observation failure remains authoritative.
  }
  throw error;
} finally {
  satellite?.close();
  await trpc?.close().catch(() => undefined);
  const cleanupStartedAt = new Date().toISOString();
  let composeRemoved = false;
  let cleanupError = null;
  try {
    await compose('down', '--volumes', '--remove-orphans', '--rmi', 'local');
    composeRemoved = (await compose('ps', '--quiet', '--all')).stdout.trim() === '';
  } catch (error) {
    cleanupError = error instanceof Error ? error.message : String(error);
  }
  const cleanupHost = captureHostSnapshot(serial, {
    includeOwners: true,
    previousDevicePath: beforeNode.devicePath,
  });
  const cleanupOwners = cleanupHost.hidraw
    .filter((entry) => entry.serialMatches)
    .map((entry) => ({
      devicePath: entry.devicePath,
      owner: entry.owner ?? ownerObservation(entry.devicePath),
    }));
  cleanup = {
    startedAt: cleanupStartedAt,
    completedAt: new Date().toISOString(),
    composeRemoved,
    host: cleanupHost,
    owners: cleanupOwners,
    successful:
      composeRemoved &&
      cleanupHost.state === 'present' &&
      cleanupOwners.length === 1 &&
      cleanupOwners.every(({ owner }) => owner.observed && owner.pids.length === 0),
    error: cleanupError,
  };
  if (run) {
    run.cleanup = cleanup;
    const evidence = { ...run, evidenceSha256: sha256Canonical(run) };
    await writeFile(
      path.join(evidenceDirectory, 'run.json'),
      `${JSON.stringify(evidence, null, 2)}\n`,
      { mode: 0o600 }
    );
  } else {
    await writeFile(
      path.join(evidenceDirectory, 'failure.json'),
      `${JSON.stringify(
        {
          schemaVersion: 'overlaykit-h039-failure/v1',
          hypothesis: 'H-039',
          runId: id,
          classification: 'inconclusive',
          failedAt: new Date().toISOString(),
          message: primaryError instanceof Error ? primaryError.message : String(primaryError),
          cleanup,
        },
        null,
        2
      )}\n`,
      { mode: 0o600 }
    );
  }
  if (!cleanup.successful && primaryError === null) {
    throw new Error('H-039 evidence completed but cleanup failed closed');
  }
}

const completedRunPath = path.join(evidenceDirectory, 'run.json');
await command(process.execPath, [path.join(LAB_DIRECTORY, 'verify.mjs'), completedRunPath], {
  cwd: REPOSITORY_ROOT,
  inherit: true,
});
process.stdout.write(`${completedRunPath}\n`);
