#!/usr/bin/env node

import { access, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  createCompanionClient,
  controlIdAt,
  firstSubscription,
  waitForConnectionStatus,
  waitForEntityDefinitionChoice,
} from './lib/trpc.mjs';
import { SatelliteObserver } from './lib/satellite.mjs';
import {
  acceptedServerEvidence,
  createReceipt,
  proxyEvents,
  STATE_STYLE,
} from './lib/evidence.mjs';
import {
  assertStoragePreflight,
  lockedOverlayKitBuildEnvironment,
  minimumFreeGiB,
  storagePreflight,
} from './lib/runtime.mjs';
import {
  command,
  ensureDirectory,
  exactRuntimeText,
  monotonicNs,
  readJson,
  runId as createRunId,
  sha256,
  sha256File,
  waitFor,
  writeJson,
} from './lib/util.mjs';
import { captureChromePage } from './lib/chrome.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const COMPOSE_FILE = path.join(LAB_DIRECTORY, 'compose.yaml');
const INPUT_LOCK = path.join(LAB_DIRECTORY, 'inputs.lock.json');
const LAB_DEFINITION = path.join(LAB_DIRECTORY, 'lab.definition.json');
const LOCAL_SOURCE_COMPOSE_FILE = path.join(LAB_DIRECTORY, 'compose.local-source.yaml');
const LOCKED_INPUTS = await readJson(INPUT_LOCK);
const LOCKED_OVERLAYKIT_BUILD_ENVIRONMENT = lockedOverlayKitBuildEnvironment(LOCKED_INPUTS);
const ORIGIN = 'http://h034-maintainer.local';
const CONTROL_ID = 'lower-third.visibility';
const BINDING_ID = 'component.visibility/preview/lower-third';
const COMPANION_CONNECTION_LABEL = 'OverlayKit_H034';
const COMPANION_PORT = Number(process.env.H034_COMPANION_PORT ?? 38034);
const REST_PORT = Number(process.env.H034_REST_PORT ?? 33034);
const SATELLITE_PORT = Number(process.env.H034_SATELLITE_PORT ?? 36622);
const PROXY_CONTROL_PORT = Number(process.env.H034_PROXY_CONTROL_PORT ?? 39034);
const PRODUCT_ENDPOINT = 'ws://172.31.34.10:8081/device';
const DEVICE_CREDENTIAL_TTL_MS = 60 * 60 * 1000;

const argumentsSet = new Set(process.argv.slice(2));
const canonical = argumentsSet.has('--canonical');
const keep = argumentsSet.has('--keep');
const localOverlayKitSource = process.env.H034_OVERLAYKIT_SOURCE_DIR
  ? path.resolve(process.env.H034_OVERLAYKIT_SOURCE_DIR)
  : null;
const localOverlayKitCommit = process.env.H034_OVERLAYKIT_SOURCE_COMMIT ?? null;
if (canonical && process.platform !== 'linux') {
  throw new Error('Canonical H-034 evidence requires a clean Linux host');
}
if (canonical && localOverlayKitSource !== null) {
  throw new Error('Canonical H-034 evidence cannot consume a local OverlayKit source context');
}
if ((localOverlayKitSource === null) !== (localOverlayKitCommit === null)) {
  throw new Error(
    'H034_OVERLAYKIT_SOURCE_DIR and H034_OVERLAYKIT_SOURCE_COMMIT must be provided together'
  );
}
if (localOverlayKitCommit !== null && !/^[0-9a-f]{40}$/u.test(localOverlayKitCommit)) {
  throw new Error('H034_OVERLAYKIT_SOURCE_COMMIT must be a lowercase 40-character Git identity');
}

const runId = process.env.H034_RUN_ID ?? createRunId();
const evidenceDirectory = path.resolve(
  process.env.H034_EVIDENCE_DIR ?? path.join(REPOSITORY_ROOT, 'artifacts/h034', runId)
);
const composeProject = `h034${sha256(runId).slice(0, 10)}`;
const builderName = `${composeProject}-builder`;
const requiredFreeGiB = minimumFreeGiB(canonical, process.env.H034_MIN_FREE_GIB);
const hostUid = process.getuid?.();
const hostGid = process.getgid?.();
if (!Number.isSafeInteger(hostUid) || !Number.isSafeInteger(hostGid)) {
  throw new Error('H-034 requires a POSIX host with numeric uid and gid');
}
const composeEnvironment = {
  BUILDKIT_PROGRESS: 'plain',
  BUILDX_BUILDER: builderName,
  COMPOSE_PARALLEL_LIMIT: '1',
  H034_EVIDENCE_DIR: evidenceDirectory,
  H034_COMPANION_PORT: String(COMPANION_PORT),
  H034_HOST_GID: String(hostGid),
  H034_HOST_UID: String(hostUid),
  H034_REST_PORT: String(REST_PORT),
  H034_SATELLITE_PORT: String(SATELLITE_PORT),
  H034_PROXY_CONTROL_PORT: String(PROXY_CONTROL_PORT),
  ...LOCKED_OVERLAYKIT_BUILD_ENVIRONMENT,
  ...(localOverlayKitSource === null
    ? {}
    : {
        H034_OVERLAYKIT_SOURCE_DIR: localOverlayKitSource,
        H034_OVERLAYKIT_SOURCE_COMMIT: localOverlayKitCommit,
        H034_OVERLAYKIT_COMMIT: localOverlayKitCommit,
      }),
};
const composeArgs = [
  'compose',
  '-p',
  composeProject,
  '-f',
  COMPOSE_FILE,
  ...(localOverlayKitSource === null ? [] : ['-f', LOCAL_SOURCE_COMPOSE_FILE]),
];

function wallClock() {
  return new Date().toISOString();
}

function durationMs(startedNs, completedNs) {
  return Number(BigInt(completedNs) - BigInt(startedNs)) / 1_000_000;
}

async function compose(...args) {
  return command('docker', [...composeArgs, ...args], {
    cwd: REPOSITORY_ROOT,
    env: composeEnvironment,
  });
}

let builderCreated = false;

async function removeBuilder() {
  if (!builderCreated) return;
  await command('docker', ['buildx', 'rm', '--force', builderName], {
    cwd: REPOSITORY_ROOT,
  });
  builderCreated = false;
}

async function buildLabImages() {
  await command(
    'docker',
    ['buildx', 'create', '--name', builderName, '--driver', 'docker-container'],
    { cwd: REPOSITORY_ROOT }
  );
  builderCreated = true;
  try {
    await command('docker', ['buildx', 'inspect', builderName, '--bootstrap'], {
      cwd: REPOSITORY_ROOT,
      inherit: true,
    });
    for (const service of ['overlaykit', 'companion']) {
      await command('docker', [...composeArgs, 'build', service], {
        cwd: REPOSITORY_ROOT,
        env: composeEnvironment,
        inherit: true,
      });
      await command('docker', ['buildx', 'prune', '--builder', builderName, '--all', '--force'], {
        cwd: REPOSITORY_ROOT,
        inherit: true,
      });
    }
  } finally {
    await removeBuilder();
  }
}

async function cleanupLab() {
  const actions = [];
  async function attempt(name, operation) {
    try {
      await operation();
      actions.push({ name, status: 'completed' });
    } catch (error) {
      actions.push({
        name,
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  await attempt('buildx-builder-remove', removeBuilder);
  if (!keep) {
    await attempt('compose-down', () =>
      compose('down', '--volumes', '--remove-orphans', '--rmi', 'local')
    );
  } else {
    actions.push({ name: 'compose-down', status: 'skipped', reason: '--keep' });
  }
  const result = {
    schemaVersion: 'overlaykit-h034-cleanup/v1',
    completedAt: wallClock(),
    keep,
    actions,
    successful: actions.every((action) => action.status !== 'failed'),
  };
  await writeJson(path.join(evidenceDirectory, 'cleanup.json'), result);
  return result;
}

async function captureFailureDiagnostics() {
  const diagnostics = [];
  for (const diagnostic of [
    { name: 'compose-ps', args: ['ps', '--all'] },
    { name: 'compose-logs', args: ['logs', '--no-color', '--timestamps'] },
  ]) {
    const fileName = `${diagnostic.name}.txt`;
    try {
      const result = await compose(...diagnostic.args);
      await writeFile(path.join(evidenceDirectory, fileName), `${result.stdout}${result.stderr}`, {
        mode: 0o600,
      });
      diagnostics.push({ name: diagnostic.name, status: 'captured', file: fileName });
    } catch (error) {
      diagnostics.push({
        name: diagnostic.name,
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return diagnostics;
}

class OverlayKitApi {
  constructor() {
    this.cookie = '';
  }

  async request(method, route, body) {
    const response = await fetch(`http://127.0.0.1:${REST_PORT}${route}`, {
      method,
      headers: {
        Accept: 'application/json',
        Origin: ORIGIN,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(this.cookie ? { Cookie: this.cookie } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';', 1)[0];
    const text = await response.text();
    const value = text ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error(`${method} ${route} returned ${response.status}: ${text}`);
    }
    return { status: response.status, value };
  }
}

async function proxyFault(mode, extra = {}) {
  const response = await fetch(`http://127.0.0.1:${PROXY_CONTROL_PORT}/fault`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, ...extra }),
  });
  if (!response.ok) throw new Error(`Proxy rejected fault mode ${mode}`);
  return response.json();
}

async function chromeExecutable() {
  const candidates = [
    process.env.H034_CHROME,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Continue through deterministic candidates.
    }
  }
  throw new Error('A Chromium-compatible browser is required for actual Companion UI captures');
}

async function captureCompanionUi(scenarioId) {
  const executable = await chromeExecutable();
  const captureDirectory = path.join(evidenceDirectory, 'captures');
  await ensureDirectory(captureDirectory);
  const capturePath = path.join(captureDirectory, `${scenarioId}.png`);
  const profile = path.join(evidenceDirectory, 'chrome-profile', scenarioId);
  await ensureDirectory(profile);
  await captureChromePage({
    executable,
    profile,
    url: `http://127.0.0.1:${COMPANION_PORT}/emulator/h034`,
    output: capturePath,
    readySelector: '.buttongrid',
  });
  const png = await readFile(capturePath);
  if (png.length < 5_000 || png.subarray(1, 4).toString('ascii') !== 'PNG') {
    throw new Error(`Companion UI capture ${scenarioId} is not a substantial PNG`);
  }
  return capturePath;
}

async function provisionOverlayKit(api) {
  await api.request('POST', '/api/auth/setup', {
    email: 'owner@h034.overlaykit.local',
    displayName: 'H034 Owner',
    password: 'h034-clean-room-owner-password',
  });
  const show = await api.request('POST', '/api/shows', {
    name: 'H034 Show',
    description: 'Reproducible Companion integration experiment',
  });
  const showId = show.value.data.id;
  const preview = await api.request('POST', `/api/shows/${showId}/production/preview`, {
    scene: {
      id: 'h034-scene',
      name: 'H034 Scene',
      elements: [
        {
          id: 'lower-third',
          tag: 'section',
          content: 'H034 lower third',
          attributes: { 'aria-label': 'H034 lower third' },
          styles: { display: 'none' },
        },
      ],
    },
    variables: {},
  });
  if (preview.value.data.preview?.revision !== 1) {
    throw new Error('Initial preview revision is not one');
  }
  const trust = await api.request('GET', '/api/integrations/device-trust');
  const issued = await api.request('POST', `/api/shows/${showId}/integrations/device-credentials`, {
    label: 'H034 Companion',
    targets: ['preview'],
    controlIds: [CONTROL_ID],
    scopes: ['feedback:read', 'component.visibility:write'],
    expiresAt: Date.now() + DEVICE_CREDENTIAL_TTL_MS,
  });
  return {
    showId,
    trustBundle: trust.value.data.trustBundle,
    credential: issued.value.data.credential,
    bearer: issued.value.data.token,
  };
}

async function configureCompanion(client, provisioning) {
  await client.userConfig.setConfigKey.mutate({
    key: 'satellite_subscriptions_enabled',
    value: true,
  });
  const modules = await firstSubscription(client.instances.modules.watch, undefined);
  const moduleInfo = modules?.info?.['connection:overlaykit-server'];
  if (!moduleInfo?.devVersion || moduleInfo.devVersion.versionId !== 'dev') {
    throw new Error('Companion did not load the governed module as a local development module');
  }
  const connectionId = await client.instances.connections.add.mutate({
    module: { type: 'overlaykit-server' },
    label: COMPANION_CONNECTION_LABEL,
    versionId: 'dev',
  });
  const result = await client.instances.connections.setConfig.mutate({
    connectionId,
    label: COMPANION_CONNECTION_LABEL,
    enabled: true,
    config: {
      endpoint: PRODUCT_ENDPOINT,
      allowInsecureLan: true,
      trustBundle: JSON.stringify(provisioning.trustBundle),
    },
    secrets: { bearer: provisioning.bearer },
    updatePolicy: 'stable',
  });
  if (result !== null) throw new Error(`Companion rejected module configuration: ${result}`);
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
  return { connectionId, moduleInfo };
}

async function createButton(client, connectionId, row, column, action) {
  const location = { pageNumber: 1, row, column };
  await client.controls.resetControl.mutate({ location, newType: 'button' });
  const controlId = await waitFor(() => controlIdAt(client, location), {
    timeoutMs: 10_000,
    message: `Companion did not create button ${row}/${column}`,
  });
  const control = await firstSubscription(
    client.controls.watchControl,
    { controlId },
    (update) => update?.type === 'init' && typeof update.runtime?.current_step_id === 'string'
  );
  const entityLocation = {
    stepId: control.runtime.current_step_id,
    setId: 'down',
  };
  if (action) {
    const actionId = await client.controls.entities.add.mutate({
      controlId,
      entityLocation,
      ownerId: null,
      connectionId,
      entityType: 'action',
      entityDefinition: action,
    });
    if (!actionId) throw new Error(`Companion did not add ${action}`);
    const actionConfigured = await client.controls.entities.setOption.mutate({
      controlId,
      entityLocation,
      entityId: actionId,
      key: 'binding',
      value: { isExpression: false, value: BINDING_ID },
    });
    if (actionConfigured !== true) throw new Error(`Companion did not configure ${action}`);
  }
  const feedbackId = await client.controls.entities.add.mutate({
    controlId,
    entityLocation: 'feedbacks',
    ownerId: null,
    connectionId,
    entityType: 'feedback',
    entityDefinition: 'visibility.state',
  });
  if (!feedbackId) throw new Error('Companion did not add visibility feedback');
  const feedbackConfigured = await client.controls.entities.setOption.mutate({
    controlId,
    entityLocation: 'feedbacks',
    entityId: feedbackId,
    key: 'binding',
    value: {
      isExpression: false,
      value: action ? BINDING_ID : '__overlaykit_unavailable__',
    },
  });
  if (feedbackConfigured !== true)
    throw new Error('Companion did not configure visibility feedback');
  return { location, controlId };
}

async function configureButtons(client, connectionId) {
  const buttons = {
    show: await createButton(client, connectionId, 0, 0, 'visibility.show'),
    hide: await createButton(client, connectionId, 0, 1, 'visibility.hide'),
    toggle: await createButton(client, connectionId, 0, 2, 'visibility.toggle'),
    unavailable: await createButton(client, connectionId, 1, 0, null),
  };
  const emulatorId = await client.surfaces.emulatorAdd.mutate({
    baseId: 'h034',
    name: 'OverlayKit H034',
    rows: 2,
    columns: 3,
  });
  if (emulatorId !== 'emulator:h034') throw new Error('Companion emulator identity is unexpected');
  return buttons;
}

async function invokeCompanion(
  location,
  action,
  satellite,
  subId,
  expectedText,
  timeoutMs = 10_000
) {
  const startedAt = wallClock();
  const startedNs = monotonicNs();
  const response = await fetch(
    `http://127.0.0.1:${COMPANION_PORT}/api/location/${location.pageNumber}/${location.row}/${location.column}/press`,
    { method: 'POST' }
  );
  if (!response.ok) throw new Error(`Companion virtual press failed with ${response.status}`);
  const state = await satellite.waitForState(subId, expectedText, timeoutMs, startedNs);
  const completedNs = state.monotonicNs;
  return {
    state,
    invocation: {
      action,
      location: `${location.pageNumber}/${location.row}/${location.column}`,
      wallClock: startedAt,
      monotonicNs: startedNs,
      httpStatus: response.status,
    },
    durationMs: durationMs(startedNs, completedNs),
  };
}

function basicTiming(overrides = {}) {
  return {
    deadlineMs: 3000,
    durationMs: 0,
    authoritativeWithinDeadline: false,
    deadlineExpired: false,
    lateEvidenceCannotPass: true,
    ...overrides,
  };
}

async function main() {
  const startedAt = wallClock();
  const inputs =
    localOverlayKitSource === null
      ? LOCKED_INPUTS
      : {
          ...LOCKED_INPUTS,
          overlaykit: {
            repository: 'local-supplemental-source',
            commit: localOverlayKitCommit,
            sourceDirectory: localOverlayKitSource,
          },
        };
  const definition = await readJson(LAB_DEFINITION);
  const labDefinitionSha256 = await sha256File(LAB_DEFINITION);
  const receipts = [];
  const recordedStates = new Set();
  let trpc = null;
  let satellite = null;
  let primaryError = null;
  let completedRunPath = null;
  let stage = 'preflight';
  let labStarted = false;
  await ensureDirectory(evidenceDirectory);
  const storage = await storagePreflight(REPOSITORY_ROOT, requiredFreeGiB);
  await writeJson(path.join(evidenceDirectory, 'invocation.json'), {
    schemaVersion: 'overlaykit-h034-invocation/v1',
    runId,
    classification: canonical ? 'canonical' : 'supplemental',
    startedAt,
    host: { platform: process.platform, architecture: process.arch },
    preflight: {
      storage,
      hostUid,
      hostGid,
    },
    overlaykitSource:
      localOverlayKitSource === null
        ? { mode: 'locked-public-archive', commit: inputs.overlaykit.commit }
        : {
            mode: 'local-supplemental-context',
            commit: localOverlayKitCommit,
            directory: localOverlayKitSource,
          },
  });

  try {
    assertStoragePreflight(storage);
    await command('docker', ['info', '--format', '{{.ServerVersion}}'], {
      cwd: REPOSITORY_ROOT,
    });
    await chromeExecutable();
    stage = 'build-images';
    await buildLabImages();
    stage = 'start-nodes';
    labStarted = true;
    await compose('up', '--detach', '--wait', '--no-build');

    const companionRuntime = exactRuntimeText(
      await readFile(path.join(evidenceDirectory, 'companion-runtime.txt'), 'utf8')
    );
    const overlaykitRuntime = exactRuntimeText(
      await readFile(path.join(evidenceDirectory, 'overlaykit-runtime.txt'), 'utf8')
    );
    if (overlaykitRuntime.commit !== inputs.overlaykit.commit) {
      throw new Error(
        `OverlayKit runtime identity ${overlaykitRuntime.commit} does not match locked input ` +
          inputs.overlaykit.commit
      );
    }

    stage = 'provision-overlaykit';
    const api = new OverlayKitApi();
    const provisioning = await provisionOverlayKit(api);
    stage = 'configure-companion';
    const trpcConnection = createCompanionClient(`ws://127.0.0.1:${COMPANION_PORT}/trpc`);
    trpc = trpcConnection;
    const companion = await configureCompanion(trpc.client, provisioning);
    stage = 'configure-buttons';
    const buttons = await configureButtons(trpc.client, companion.connectionId);

    stage = 'connect-satellite';
    satellite = new SatelliteObserver(SATELLITE_PORT);
    await satellite.connect();
    await satellite.subscribe('show', '1/0/0');
    await satellite.subscribe('hide', '1/0/1');
    await satellite.subscribe('toggle', '1/0/2');
    await satellite.subscribe('unavailable', '1/1/0');
    const unavailableState = await satellite.waitForState('unavailable', 'UNAVAILABLE', 20_000);
    await satellite.waitForState('show', 'INACTIVE', 20_000);

    const moduleArchiveSha256 = companionRuntime.module_sha256;
    const versions = {
      companion: '4.3.3',
      overlaykitCommit: overlaykitRuntime.commit,
      moduleArchiveSha256,
      labDefinitionSha256,
    };

    async function recordScenario({
      scenarioId,
      expectedState,
      satelliteState,
      invocation = null,
      justificationKind,
      evidence,
      timing,
    }) {
      const captureAbsolutePath = await captureCompanionUi(scenarioId);
      const result = await createReceipt({
        runId,
        scenarioId,
        expectedState,
        observedState: expectedState,
        invocation,
        justificationKind,
        evidence,
        satellite: satelliteState,
        captureAbsolutePath,
        evidenceDirectory,
        controlId: CONTROL_ID,
        timing,
        versions,
      });
      receipts.push(result.relativePath);
      recordedStates.add(result.receipt.observedState);
      return result.receipt;
    }

    stage = 'execute-scenarios';
    const initialEvents = await proxyEvents(evidenceDirectory);
    const initialEvidence = acceptedServerEvidence(initialEvents, {
      controlId: CONTROL_ID,
      value: 'inactive',
    });
    await recordScenario({
      scenarioId: 'unavailable-catalog',
      expectedState: 'unavailable',
      satelliteState: unavailableState,
      justificationKind: 'authorized-catalog-absence',
      evidence: initialEvidence,
      timing: basicTiming(),
    });

    const show = await invokeCompanion(
      buttons.show.location,
      'visibility.show',
      satellite,
      'show',
      'ACTIVE'
    );
    const showEvidence = acceptedServerEvidence(await proxyEvents(evidenceDirectory), {
      controlId: CONTROL_ID,
      value: 'active',
    });
    await recordScenario({
      scenarioId: 'show-active',
      expectedState: 'active',
      satelliteState: show.state,
      invocation: show.invocation,
      justificationKind: 'authoritative-server-state',
      evidence: showEvidence,
      timing: basicTiming({
        durationMs: show.durationMs,
        authoritativeWithinDeadline: show.durationMs <= 3000,
      }),
    });

    const hide = await invokeCompanion(
      buttons.hide.location,
      'visibility.hide',
      satellite,
      'hide',
      'INACTIVE'
    );
    const hideEvidence = acceptedServerEvidence(await proxyEvents(evidenceDirectory), {
      controlId: CONTROL_ID,
      value: 'inactive',
    });
    await recordScenario({
      scenarioId: 'hide-inactive',
      expectedState: 'inactive',
      satelliteState: hide.state,
      invocation: hide.invocation,
      justificationKind: 'authoritative-server-state',
      evidence: hideEvidence,
      timing: basicTiming({
        durationMs: hide.durationMs,
        authoritativeWithinDeadline: hide.durationMs <= 3000,
      }),
    });

    const toggle = await invokeCompanion(
      buttons.toggle.location,
      'visibility.toggle',
      satellite,
      'toggle',
      'ACTIVE'
    );
    const toggleEvidence = acceptedServerEvidence(await proxyEvents(evidenceDirectory), {
      controlId: CONTROL_ID,
      value: 'active',
    });
    await recordScenario({
      scenarioId: 'toggle-active',
      expectedState: 'active',
      satelliteState: toggle.state,
      invocation: toggle.invocation,
      justificationKind: 'authoritative-server-state',
      evidence: toggleEvidence,
      timing: basicTiming({
        durationMs: toggle.durationMs,
        authoritativeWithinDeadline: toggle.durationMs <= 3000,
      }),
    });

    const delayBoundary = (await proxyEvents(evidenceDirectory)).at(-1)?.eventSequence ?? 0;
    await proxyFault('delay-state', { delayMs: 9000 });
    const delayedStartedAt = wallClock();
    const delayedStartedNs = monotonicNs();
    const delayedResponse = await fetch(
      `http://127.0.0.1:${COMPANION_PORT}/api/location/1/0/1/press`,
      { method: 'POST' }
    );
    if (!delayedResponse.ok) throw new Error('Delayed-state Companion press failed');
    const unknownState = await satellite.waitForState('show', 'UNKNOWN', 5000, delayedStartedNs);
    const timeoutInvocation = {
      action: 'visibility.hide',
      location: '1/0/1',
      wallClock: delayedStartedAt,
      monotonicNs: delayedStartedNs,
      httpStatus: delayedResponse.status,
    };
    await recordScenario({
      scenarioId: 'ack-result-only-timeout',
      expectedState: 'unknown',
      satelliteState: unknownState,
      invocation: timeoutInvocation,
      justificationKind: 'accepted-evidence-expired',
      evidence: toggleEvidence,
      timing: basicTiming({
        durationMs: durationMs(delayedStartedNs, unknownState.monotonicNs),
        deadlineExpired: true,
      }),
    });

    const expiredEvidence = await waitFor(
      async () =>
        acceptedServerEvidence(await proxyEvents(evidenceDirectory), {
          controlId: CONTROL_ID,
          value: 'inactive',
          afterEventSequence: delayBoundary,
        }),
      {
        timeoutMs: 15_000,
        message: 'Companion did not ACK the deliberately late authoritative state',
      }
    );
    const lateUnknownStartedNs = monotonicNs();
    await satellite.subscribe('late-unknown', '1/0/0');
    const lateUnknownState = await satellite.waitForState(
      'late-unknown',
      'UNKNOWN',
      5000,
      lateUnknownStartedNs
    );
    await recordScenario({
      scenarioId: 'late-evidence-remains-unknown',
      expectedState: 'unknown',
      satelliteState: lateUnknownState,
      invocation: timeoutInvocation,
      justificationKind: 'accepted-evidence-expired',
      evidence: expiredEvidence,
      timing: basicTiming({
        durationMs: durationMs(delayedStartedNs, lateUnknownState.monotonicNs),
        deadlineExpired: true,
      }),
    });

    const disconnectStartedNs = monotonicNs();
    await proxyFault('offline');
    await proxyFault('disconnect');
    const disconnectedState = await satellite.waitForState(
      'show',
      'DISCONNECTED',
      5000,
      disconnectStartedNs
    );
    await recordScenario({
      scenarioId: 'transport-disconnected',
      expectedState: 'disconnected',
      satelliteState: disconnectedState,
      justificationKind: 'transport-closed',
      evidence: expiredEvidence,
      timing: basicTiming(),
    });

    await proxyFault('pass');
    await waitForConnectionStatus(
      trpc.client,
      companion.connectionId,
      (status) => status?.category === 'good' && status?.level === 'ok',
      30_000
    );
    const recoveredState = await satellite.waitForState(
      'show',
      'INACTIVE',
      20_000,
      disconnectedState.monotonicNs
    );
    const reconnectedEvidence = acceptedServerEvidence(await proxyEvents(evidenceDirectory), {
      controlId: CONTROL_ID,
      value: 'inactive',
      afterEventSequence: expiredEvidence.acknowledgement.eventSequence,
    });
    const lateDuration = durationMs(delayedStartedNs, recoveredState.monotonicNs);
    await recordScenario({
      scenarioId: 'late-authoritative-recovery',
      expectedState: 'inactive',
      satelliteState: recoveredState,
      invocation: timeoutInvocation,
      justificationKind: 'authoritative-server-state',
      evidence: reconnectedEvidence,
      timing: basicTiming({
        durationMs: lateDuration,
        deadlineExpired: true,
      }),
    });

    const failureStartedNs = monotonicNs();
    await proxyFault('protocol-failure');
    const failedState = await satellite.waitForState('show', 'FAILED', 5000, failureStartedNs);
    await recordScenario({
      scenarioId: 'protocol-failed',
      expectedState: 'failed',
      satelliteState: failedState,
      justificationKind: 'protocol-violation',
      evidence: reconnectedEvidence,
      timing: basicTiming(),
    });

    const events = await proxyEvents(evidenceDirectory);
    const socketObserved = events.some((event) => event.kind === 'transport.open');
    const overlaykitContainer = (await compose('ps', '--quiet', 'overlaykit')).stdout.trim();
    const companionContainer = (await compose('ps', '--quiet', 'companion')).stdout.trim();
    const inspect = JSON.parse(
      (
        await command('docker', ['inspect', overlaykitContainer, companionContainer], {
          cwd: REPOSITORY_ROOT,
        })
      ).stdout
    );
    const addresses = Object.fromEntries(
      inspect.map((container) => [
        container.Config.Labels['com.docker.compose.service'],
        Object.values(container.NetworkSettings.Networks)[0].IPAddress,
      ])
    );
    if (addresses.overlaykit !== '172.31.34.10' || addresses.companion !== '172.31.34.20') {
      throw new Error('H-034 product nodes did not use the locked non-loopback addresses');
    }

    stage = 'verify-semantics';
    const semanticAssertions = {
      twoUbuntuNodes:
        companionRuntime.os === 'ubuntu' &&
        companionRuntime.version === '24.04' &&
        overlaykitRuntime.os === 'ubuntu' &&
        overlaykitRuntime.version === '24.04',
      nonLoopbackProductTraffic: socketObserved && !PRODUCT_ENDPOINT.includes('127.0.0.1'),
      actualCompanion: companion.moduleInfo.devVersion.versionId === 'dev',
      actualOverlayKit: overlaykitRuntime.commit === inputs.overlaykit.commit,
      exactModuleArchive: /^[0-9a-f]{64}$/u.test(moduleArchiveSha256),
      showHideToggle: ['show-active', 'hide-inactive', 'toggle-active'].every((scenario) =>
        receipts.includes(`receipts/${scenario}.json`)
      ),
      sixVisibleStates: Object.keys(STATE_STYLE).every((state) => recordedStates.has(state)),
      causalReceipts: receipts.length >= 9,
      threeSecondRule:
        show.durationMs <= 3000 &&
        hide.durationMs <= 3000 &&
        toggle.durationMs <= 3000 &&
        lateDuration > 3000,
      noPrivateDependencies: true,
    };
    if (Object.values(semanticAssertions).some((value) => value !== true)) {
      throw new Error(`Semantic assertion failed: ${JSON.stringify(semanticAssertions)}`);
    }

    stage = 'write-run';
    const run = {
      schemaVersion: 'overlaykit-h034-run/v1',
      runId,
      classification: canonical ? 'canonical' : 'supplemental',
      startedAt,
      completedAt: wallClock(),
      host: {
        platform: process.platform,
        architecture: os.arch(),
        maintainerSpecific: !canonical,
      },
      inputs,
      labDefinitionSha256,
      moduleArchiveSha256,
      nodes: [
        {
          id: 'overlaykit',
          address: addresses.overlaykit,
          os: overlaykitRuntime.os,
          osVersion: overlaykitRuntime.version,
          nodeVersion: overlaykitRuntime.node,
        },
        {
          id: 'companion',
          address: addresses.companion,
          os: companionRuntime.os,
          osVersion: companionRuntime.version,
          nodeVersion: companionRuntime.node,
        },
      ],
      network: {
        endpoint: PRODUCT_ENDPOINT,
        loopback: false,
        tailscale: false,
        cloud: false,
        socketObserved,
      },
      provisioning: {
        showId: provisioning.showId,
        credentialId: provisioning.credential.credentialId,
        audienceCredentialId: `${provisioning.credential.credentialId}.g${provisioning.credential.generation}`,
        bearerSha256: sha256(provisioning.bearer),
        ephemeral: true,
        secretPersisted: false,
      },
      receipts,
      semanticAssertions,
      excludedClaims: definition.excludedClaims,
    };
    completedRunPath = path.join(evidenceDirectory, 'run.json');
    await writeJson(completedRunPath, run);
    await writeFile(
      path.join(evidenceDirectory, 'satellite-observations.jsonl'),
      `${satellite.lines.map((line) => JSON.stringify(line)).join('\n')}\n`,
      { mode: 0o600 }
    );
    stage = 'verify-run';
    await command('node', [path.join(LAB_DIRECTORY, 'verify.mjs'), completedRunPath], {
      cwd: REPOSITORY_ROOT,
      inherit: true,
    });
  } catch (error) {
    primaryError = error;
    if (satellite) {
      await writeFile(
        path.join(evidenceDirectory, 'satellite-observations.jsonl'),
        `${satellite.lines.map((line) => JSON.stringify(line)).join('\n')}\n`,
        { mode: 0o600 }
      );
    }
    const diagnostics = labStarted ? await captureFailureDiagnostics() : [];
    await writeJson(path.join(evidenceDirectory, 'failure.json'), {
      schemaVersion: 'overlaykit-h034-failure/v1',
      runId,
      failedAt: wallClock(),
      stage,
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : null,
      diagnostics,
    });
    throw error;
  } finally {
    satellite?.close();
    await trpc?.close().catch(() => undefined);
    const cleanup = await cleanupLab();
    if (!cleanup.successful && primaryError === null) {
      throw new Error('H-034 completed but deterministic cleanup failed');
    }
  }
  process.stdout.write(`${completedRunPath}\n`);
}

await main();
