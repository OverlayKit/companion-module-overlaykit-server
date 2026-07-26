#!/usr/bin/env node

import { readFileSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { classifyFuserResult } from '../h035/inventory-lib.mjs';
import { acquisitionSignals, parseFdListing, parseProcessTable } from '../h037/acquisition-lib.mjs';
import {
  controlIdAt,
  createCompanionClient,
  firstSubscription,
  waitForConnectionStatus,
  waitForEntityDefinitionChoice,
} from '../h034/lib/trpc.mjs';
import { proxyEvents } from '../h034/lib/evidence.mjs';
import { SatelliteObserver } from '../h034/lib/satellite.mjs';
import { command, waitFor } from '../h034/lib/util.mjs';
import {
  H038_CLAIM_BOUNDARY,
  parseProcessStatus,
  parseProperties,
  runId as createRunId,
  selectCausalReceipt,
  selectGraphicalSession,
  sha256,
  sha256Canonical,
  virtualInvocationAudit,
} from './physical-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const COMPOSE_FILE = path.join(LAB_DIRECTORY, 'compose.yaml');
const INPUT_LOCK = path.join(REPOSITORY_ROOT, 'lab/h034/inputs.lock.json');
const CONTROL_ID = 'lower-third.visibility';
const BINDING_ID = 'component.visibility/preview/lower-third';
const BUTTON_LOCATION = Object.freeze({ pageNumber: 1, row: 0, column: 0 });
const COMPANION_PORT = 38038;
const REST_PORT = 33038;
const SATELLITE_PORT = 36628;
const PRODUCT_ENDPOINT = 'ws://172.30.38.10:8081/device';
const SOURCE_FILES = [
  '.overlaykit/governance/changes/CHG-0009.json',
  'lab/h038/companion-entrypoint.sh',
  'lab/h038/compose.yaml',
  'lab/h038/physical-lib.mjs',
  'lab/h038/run.mjs',
  'lab/h038/schemas/physical-run.schema.json',
  'lab/h038/verify.mjs',
];

function parseArgs(argv) {
  const result = {
    inventory: 'artifacts/h035/host-inventory-2026-07-25.json',
    acquisition: 'artifacts/h037/acquisition-2026-07-25.json',
    evidenceDirectory: null,
    windowSeconds: 45,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--inventory') result.inventory = argv[++index] ?? '';
    else if (argument === '--acquisition') result.acquisition = argv[++index] ?? '';
    else if (argument === '--evidence-dir') result.evidenceDirectory = argv[++index] ?? '';
    else if (argument === '--window-seconds') result.windowSeconds = Number(argv[++index]);
    else throw new Error(`Unknown H-038 argument: ${argument}`);
  }
  if (
    !Number.isSafeInteger(result.windowSeconds) ||
    result.windowSeconds < 10 ||
    result.windowSeconds > 120
  ) {
    throw new Error('H-038 physical window must be between 10 and 120 seconds');
  }
  return result;
}

function syncCommand(program, args) {
  const result = spawnSync(program, args, {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    exitCode: result.status,
    errorCode: result.error?.code ?? null,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function ownerObservation(devicePath) {
  const result = syncCommand('fuser', ['-v', devicePath]);
  const classification = classifyFuserResult(result);
  return {
    observed: classification.observed,
    usageError: classification.usageError,
    pids: classification.pids,
    exitCode: result.exitCode,
    errorCode: result.errorCode,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
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
    sessions.push(parseProperties(observed.stdout));
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
    email: 'owner@h038.overlaykit.local',
    displayName: 'H038 Owner',
    password: 'h038-ephemeral-owner-password',
  });
  const show = await api.request('POST', '/api/shows', {
    name: 'H038 Physical Button',
    description: 'Ephemeral governed physical-input experiment',
  });
  const showId = show.data.id;
  await api.request('POST', `/api/shows/${showId}/production/preview`, {
    scene: {
      id: 'h038-scene',
      name: 'H038 Scene',
      elements: [
        {
          id: 'lower-third',
          tag: 'section',
          content: 'H038 lower third',
          attributes: { 'aria-label': 'H038 lower third' },
          styles: { display: 'none' },
        },
      ],
    },
    variables: {},
  });
  const trust = await api.request('GET', '/api/integrations/device-trust');
  const issued = await api.request('POST', `/api/shows/${showId}/integrations/device-credentials`, {
    label: 'H038 Companion',
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
      label: 'OverlayKit_H038',
      versionId: 'dev',
    })
  );
  const configError = await mutate('instances.connections.setConfig', () =>
    client.instances.connections.setConfig.mutate({
      connectionId,
      label: 'OverlayKit_H038',
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
  if (configError !== null) throw new Error(`Companion rejected H-038 config: ${configError}`);
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
      'visibility.show',
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
    message: 'Companion did not create the top-left physical button',
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
      entityDefinition: 'visibility.show',
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
    throw new Error('Companion did not configure the H-038 physical button');
  }
  return { connectionId, moduleInfo, controlId };
}

async function surfaceEvidence(compose, device, groupId) {
  const containerId = (await compose('ps', '--quiet', 'companion')).stdout.trim();
  const inspected = JSON.parse((await command('docker', ['inspect', containerId])).stdout)[0];
  const processes = parseProcessTable(
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
  const surface = processes.find((entry) => entry.args?.includes('SurfaceThread.js'));
  if (!surface?.pid) throw new Error('Companion lacks a physical SurfaceThread');
  const status = parseProcessStatus(
    (
      await command('docker', [
        'exec',
        '--user',
        String(surface.uid),
        containerId,
        'cat',
        `/proc/${surface.pid}/status`,
      ])
    ).stdout
  );
  const descriptors = parseFdListing(
    (
      await command('docker', [
        'exec',
        '--user',
        String(surface.uid),
        containerId,
        'ls',
        '-l',
        `/proc/${surface.pid}/fd`,
      ])
    ).stdout
  );
  const logs = (await compose('logs', '--no-color', 'companion')).stdout;
  const signals = acquisitionSignals(logs, device.devicePath, device.hid.unique);
  const evidence = {
    containerId,
    imageId: inspected.Image,
    privileged: inspected.HostConfig.Privileged,
    devices: inspected.HostConfig.Devices,
    groupAdd: inspected.HostConfig.GroupAdd ?? [],
    surface: { ...surface, ...status, fileDescriptors: descriptors },
    ownsDevice: descriptors.some(({ target }) => target === device.devicePath),
    signals,
  };
  if (
    evidence.privileged ||
    !evidence.groupAdd.includes(String(groupId)) ||
    !status.groups.includes(groupId) ||
    !evidence.ownsDevice ||
    !signals.panelReady ||
    signals.openFailed
  ) {
    throw new Error(`Companion physical acquisition receipt failed: ${JSON.stringify(evidence)}`);
  }
  return evidence;
}

const arguments_ = parseArgs(process.argv.slice(2));
const id = createRunId();
const inventoryPath = path.resolve(REPOSITORY_ROOT, arguments_.inventory);
const acquisitionPath = path.resolve(REPOSITORY_ROOT, arguments_.acquisition);
const evidenceDirectory = path.resolve(
  REPOSITORY_ROOT,
  arguments_.evidenceDirectory ?? path.join('artifacts/h038', id)
);
await mkdir(evidenceDirectory, { recursive: true });
const inventoryBytes = await readFile(inventoryPath);
const acquisitionBytes = await readFile(acquisitionPath);
const inventory = JSON.parse(inventoryBytes);
const acquisition = JSON.parse(acquisitionBytes);
if (process.version.split('.')[0] !== 'v22') throw new Error('H-038 requires Node 22');
if (
  inventory.hypothesis !== 'H-035' ||
  inventory.host.osRelease.VERSION_ID !== '43' ||
  inventory.hidraw.matches.length !== 1
) {
  throw new Error('H-038 requires exact Fedora 43 H-035 evidence');
}
if (
  acquisition.hypothesis !== 'H-037' ||
  !acquisition.positive.signals.panelReady ||
  !acquisition.positive.process.ownsDevice ||
  acquisition.input.h035FileSha256 !== sha256(inventoryBytes)
) {
  throw new Error('H-038 requires current positive H-037 acquisition evidence');
}
const device = inventory.hidraw.matches[0];
const groupId = device.before.gid;
const deviceStat = statSync(device.devicePath);
if (
  deviceStat.gid !== groupId ||
  inventory.usb.target.vendorId !== '0fd9' ||
  inventory.usb.target.productId !== '0080'
) {
  throw new Error('Current device identity or group differs from H-035');
}
const session = await graphicalSession(inventory.host.principal.user);
const beforeOwner = ownerObservation(device.devicePath);
if (!beforeOwner.observed || beforeOwner.pids.length > 0) {
  throw new Error('H-038 requires an initially unowned physical device');
}

const lockedInputs = await readJson(INPUT_LOCK);
const composeProject = `h038${sha256(id).slice(0, 10)}`;
const composeEnvironment = {
  H034_HOST_GID: String(inventory.host.principal.gid),
  H034_HOST_UID: String(inventory.host.principal.uid),
  H034_OVERLAYKIT_ARCHIVE_SHA256: lockedInputs.overlaykit.archiveSha256,
  H034_OVERLAYKIT_COMMIT: lockedInputs.overlaykit.commit,
  H038_COMPANION_PORT: String(COMPANION_PORT),
  H038_DEVICE_GID: String(groupId),
  H038_DEVICE_PATH: device.devicePath,
  H038_EVIDENCE_DIR: evidenceDirectory,
  H038_LAB_DIR: LAB_DIRECTORY,
  H038_REST_PORT: String(REST_PORT),
  H038_SATELLITE_PORT: String(SATELLITE_PORT),
};
const composeArgs = ['compose', '-p', composeProject, '-f', COMPOSE_FILE];
const compose = (...args) =>
  command('docker', [...composeArgs, ...args], { cwd: REPOSITORY_ROOT, env: composeEnvironment });
const invocationEntries = [];
const startedAt = new Date().toISOString();
let trpc = null;
let satellite = null;
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
  const surface = await surfaceEvidence(compose, device, groupId);
  const api = new OverlayKitApi(invocationEntries);
  const provisioning = await provisionOverlayKit(api);
  trpc = createCompanionClient(`ws://127.0.0.1:${COMPANION_PORT}/trpc`);
  const companion = await configureCompanion(trpc.client, provisioning, invocationEntries);
  satellite = new SatelliteObserver(SATELLITE_PORT);
  await satellite.connect();
  await satellite.subscribe('physical', '1/0/0');
  await satellite.waitForState('physical', 'INACTIVE', 20_000);
  const eventsBefore = await proxyEvents(evidenceDirectory);
  const afterEventSequence = eventsBefore.at(-1)?.eventSequence ?? 0;
  const challenge = sha256(`${id}:${device.hid.unique}:${afterEventSequence}`).slice(0, 12);
  const windowOpenedAt = new Date().toISOString();
  const windowOpenedNs = process.hrtime.bigint().toString();
  process.stdout.write(
    `H-038 ${challenge}: pulsa UNA VEZ la tecla superior izquierda del Stream Deck MK.2 en ${arguments_.windowSeconds}s.\n`
  );
  const [causal, satelliteState] = await Promise.all([
    waitFor(
      async () => {
        try {
          return selectCausalReceipt(await proxyEvents(evidenceDirectory), {
            afterEventSequence,
            controlId: CONTROL_ID,
            expectedValue: 'active',
          });
        } catch {
          return null;
        }
      },
      {
        timeoutMs: arguments_.windowSeconds * 1000,
        intervalMs: 50,
        message: 'No physical button command reached authoritative OverlayKit state',
      }
    ),
    satellite.waitForState('physical', 'ACTIVE', arguments_.windowSeconds * 1000, windowOpenedNs),
  ]);
  const audit = virtualInvocationAudit(invocationEntries);
  if (!audit.passed) throw new Error('H-038 invoked a forbidden virtual-press path');
  const manifest = await readJson(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
  );
  const sourceSha256 = Object.fromEntries(
    SOURCE_FILES.map((relativePath) => [
      relativePath,
      sha256(readFileSync(path.join(REPOSITORY_ROOT, relativePath))),
    ])
  );
  run = {
    schemaVersion: 'overlaykit-h038-physical-run/v1',
    hypothesis: 'H-038',
    runId: id,
    startedAt,
    completedAt: new Date().toISOString(),
    collector: {
      node: process.version,
      commit: (await command('git', ['rev-parse', 'HEAD'], { cwd: REPOSITORY_ROOT })).stdout.trim(),
      governanceManifestContentHash: manifest.contentHash,
      sourceSha256,
    },
    inputs: {
      h035Path: path.relative(REPOSITORY_ROOT, inventoryPath),
      h035FileSha256: sha256(inventoryBytes),
      h035EvidenceSha256: inventory.evidenceSha256,
      h037Path: path.relative(REPOSITORY_ROOT, acquisitionPath),
      h037FileSha256: sha256(acquisitionBytes),
      h037EvidenceSha256: acquisition.evidenceSha256,
      lockedInputs,
    },
    host: {
      osVersion: inventory.host.osRelease.VERSION_ID,
      kernel: inventory.host.kernel,
      architecture: inventory.host.architecture,
      principal: inventory.host.principal,
      graphicalSession: session.selected,
    },
    device: {
      vendorId: inventory.usb.target.vendorId,
      productId: inventory.usb.target.productId,
      model: device.hid.name,
      serial: device.hid.unique,
      devicePath: device.devicePath,
      gid: groupId,
    },
    companion: {
      version: lockedInputs.companion.version,
      sourceCommit: lockedInputs.companion.sourceCommit,
      surface,
      moduleVersionId: companion.moduleInfo.devVersion.versionId,
      connectionId: companion.connectionId,
      controlId: companion.controlId,
      location: BUTTON_LOCATION,
    },
    physicalWindow: {
      challenge,
      openedAt: windowOpenedAt,
      openedMonotonicNs: windowOpenedNs,
      timeoutSeconds: arguments_.windowSeconds,
      instruction: 'press top-left physical MK.2 key exactly once',
    },
    invocationAudit: audit,
    causalReceipt: causal,
    companionObservation: satelliteState,
    provisioning: {
      showId: provisioning.showId,
      credentialId: provisioning.credentialId,
      bearerSha256: sha256(provisioning.bearer),
      ephemeral: true,
    },
    before: { owner: beforeOwner },
    claimBoundary: H038_CLAIM_BOUNDARY,
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
    // The primary failure remains authoritative when diagnostics are unavailable.
  }
  throw error;
} finally {
  satellite?.close();
  await trpc?.close().catch(() => undefined);
  const cleanupStartedAt = new Date().toISOString();
  try {
    await compose('down', '--volumes', '--remove-orphans', '--rmi', 'local');
    const afterOwner = ownerObservation(device.devicePath);
    cleanup = {
      startedAt: cleanupStartedAt,
      completedAt: new Date().toISOString(),
      composeRemoved: true,
      owner: afterOwner,
      successful: afterOwner.observed && afterOwner.pids.length === 0,
    };
  } catch (error) {
    cleanup = {
      startedAt: cleanupStartedAt,
      completedAt: new Date().toISOString(),
      composeRemoved: false,
      owner: ownerObservation(device.devicePath),
      successful: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
  if (run) {
    run.cleanup = cleanup;
    const evidence = { ...run, evidenceSha256: sha256Canonical(run) };
    await writeFile(
      path.join(evidenceDirectory, 'run.json'),
      `${JSON.stringify(evidence, null, 2)}\n`,
      {
        mode: 0o600,
      }
    );
  } else {
    await writeFile(
      path.join(evidenceDirectory, 'failure.json'),
      `${JSON.stringify(
        {
          schemaVersion: 'overlaykit-h038-failure/v1',
          hypothesis: 'H-038',
          runId: id,
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
    throw new Error('H-038 evidence succeeded but cleanup failed closed');
  }
}

const completedRunPath = path.join(evidenceDirectory, 'run.json');
await command(process.execPath, [path.join(LAB_DIRECTORY, 'verify.mjs'), completedRunPath], {
  cwd: REPOSITORY_ROOT,
  inherit: true,
});
process.stdout.write(`${completedRunPath}\n`);
