import { createHash, randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { ClientRequest } from 'node:http';
import WebSocket, { type RawData } from 'ws';
import {
  DEVICE_BOOTSTRAP_SNAPSHOT_TYPE,
  DEVICE_READY_TYPE,
  buildDeviceReadyMessage,
  parseDeviceBootstrapSnapshotMessage,
} from '@overlaykit/protocol/device-bootstrap';
import { DEFAULT_CONTROL_FEEDBACK_TIMEOUT_MS } from '@overlaykit/protocol/control-feedback';
import {
  DEVICE_COMMAND_EXECUTE_TYPE,
  DEVICE_COMMAND_EXECUTE_VERSION,
  DEVICE_COMMAND_REFUSED_TYPE,
  DEVICE_COMMAND_RESULT_TYPE,
  deviceCommandExecuteBytes,
  deviceCommandIntentBytes,
  parseDeviceCommandExecute,
  parseDeviceCommandResponseMessage,
  type DeviceCommandExecute,
} from '@overlaykit/protocol/device-command';
import {
  admitDeviceControlFrame,
  projectDeviceControl,
  reduceAdmittedDeviceControlFrame,
  type AdmittedDeviceControlFrameState,
  type DeviceControlFrameAuthorityContext,
  type DeviceControlFrameIdentity,
} from '@overlaykit/protocol/device-control-frame';
import {
  DEVICE_STATE_ACK_TYPE,
  DEVICE_STATE_ACK_VERSION,
  DEVICE_STATE_DELTA_TYPE,
  parseDeviceStateDeltaMessage,
  type DeviceStateAckErrorCode,
} from '@overlaykit/protocol/device-state-sync';
import type { ComponentVisibilityActionDescriptor } from '@overlaykit/protocol/control-action-catalog';
import type { ProductionBus } from '@overlaykit/protocol/production';
import {
  validateModuleConfig,
  type ModuleConfig,
  type ModuleSecrets,
  type ValidatedModuleConfig,
} from './config.js';

const DEVICE_SUBPROTOCOL = 'overlaykit.device.v1';
const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 10_000;
const MAX_ACCEPTED_IDENTITIES = 1_000;

export type RuntimeConnectionStatus =
  'idle' | 'connecting' | 'open' | 'ready' | 'disconnected' | 'failed';
export type VisibilityMode = 'show' | 'hide' | 'toggle';
export type VisibilityFeedbackState =
  'active' | 'inactive' | 'unknown' | 'disconnected' | 'failed' | 'unavailable';

export interface VisibilityBinding {
  readonly id: string;
  readonly label: string;
  readonly showId: string;
  readonly target: ProductionBus;
  readonly componentId: string;
  readonly controlId: string;
}

export interface RuntimeSnapshot {
  readonly status: RuntimeConnectionStatus;
  readonly ready: boolean;
  readonly showId: string | null;
  readonly bindings: ReadonlyArray<VisibilityBinding>;
}

export interface RuntimeObserver {
  readonly onStatusChanged?: (status: RuntimeConnectionStatus, message: string | null) => void;
  readonly onDefinitionsChanged?: () => void;
  readonly onFeedbackChanged?: () => void;
  readonly onLog?: (level: 'debug' | 'warn' | 'error', message: string) => void;
}

export interface RuntimeScheduler {
  schedule(delayMs: number, task: () => void): unknown;
  cancel(handle: unknown): void;
}

export interface RuntimeDependencies {
  readonly createSocket?: (endpoint: string, bearer: string) => WebSocket;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly operationId?: () => string;
  readonly scheduler?: RuntimeScheduler;
}

interface PendingCommand {
  readonly bindingId: string;
  readonly requestSha256: string;
  readonly intentSha256: string;
}

function defaultSocket(endpoint: string, bearer: string): WebSocket {
  return new WebSocket(endpoint, DEVICE_SUBPROTOCOL, {
    headers: { Authorization: `Bearer ${bearer}` },
    followRedirects: false,
    perMessageDeflate: false,
    handshakeTimeout: 3_000,
    maxPayload: 1_048_576,
  });
}

function defaultScheduler(): RuntimeScheduler {
  return {
    schedule(delayMs, task) {
      return setTimeout(task, delayMs);
    },
    cancel(handle) {
      clearTimeout(handle as ReturnType<typeof setTimeout>);
    },
  };
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function messageType(value: unknown): unknown {
  return isRecord(value) ? value.type : null;
}

function rawDataText(data: RawData): string {
  if (Array.isArray(data)) return Buffer.concat(data).toString('utf8');
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString('utf8');
  return data.toString('utf8');
}

function feedbackIdentity(identity: DeviceControlFrameIdentity): string {
  return `${identity.issuerKeyId}\u0000${identity.sequence}\u0000${identity.sha256}`;
}

function targetOrder(target: ProductionBus): number {
  return target === 'preview' ? 0 : 1;
}

function errorAckCode(error: unknown): DeviceStateAckErrorCode {
  if (isRecord(error) && error.code === 'BASE_MISMATCH') return 'base_mismatch';
  if (isRecord(error) && error.code === 'CRYPTO_UNAVAILABLE') return 'resource_unavailable';
  if (isRecord(error) && typeof error.code === 'string' && error.code.startsWith('INVALID_')) {
    return 'validation_failed';
  }
  return 'apply_failed';
}

function closeCodeIsTerminal(code: number): boolean {
  return code === 1002 || code === 1003 || code === 1007 || code === 1008;
}

function responseIsTerminal(statusCode: number | undefined): boolean {
  return (
    statusCode === 400 ||
    statusCode === 401 ||
    statusCode === 403 ||
    statusCode === 404 ||
    statusCode === 405 ||
    statusCode === 409 ||
    statusCode === 426
  );
}

export class OverlayKitControlRuntime {
  private readonly observer: RuntimeObserver;
  private readonly createSocket: NonNullable<RuntimeDependencies['createSocket']>;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly operationId: () => string;
  private readonly scheduler: RuntimeScheduler;
  private config: ValidatedModuleConfig | null = null;
  private socket: WebSocket | null = null;
  private reconnectHandle: unknown | null = null;
  private reconnectAttempt = 0;
  private status: RuntimeConnectionStatus = 'idle';
  private stopping = false;
  private terminal = false;
  private ready = false;
  private showId: string | null = null;
  private audienceCredentialId: string | null = null;
  private lastAcceptedSequence = 0;
  private readonly acceptedIdentities = new Map<string, DeviceControlFrameIdentity>();
  private readonly targetStates = new Map<ProductionBus, AdmittedDeviceControlFrameState>();
  private readonly bootstrappedTargets = new Set<ProductionBus>();
  private readonly knownTargets = new Set<ProductionBus>();
  private readonly knownControlIds = new Set<string>();
  private readonly bindingsById = new Map<string, VisibilityBinding>();
  private readonly failedBindings = new Set<string>();
  private readonly pendingCommands = new Map<string, PendingCommand>();
  private readonly freshnessHandles = new Map<ProductionBus, unknown>();
  private messageTail: Promise<void> = Promise.resolve();

  constructor(observer: RuntimeObserver = {}, dependencies: RuntimeDependencies = {}) {
    this.observer = observer;
    this.createSocket = dependencies.createSocket ?? defaultSocket;
    this.now = dependencies.now ?? Date.now;
    this.random = dependencies.random ?? Math.random;
    this.operationId = dependencies.operationId ?? randomUUID;
    this.scheduler = dependencies.scheduler ?? defaultScheduler();
  }

  async start(config: ModuleConfig, secrets: ModuleSecrets): Promise<void> {
    await this.stop();
    this.resetAuthority();
    this.stopping = false;
    this.terminal = false;
    this.config = await validateModuleConfig(config, secrets);
    this.connect();
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.ready = false;
    if (this.reconnectHandle !== null) {
      this.scheduler.cancel(this.reconnectHandle);
      this.reconnectHandle = null;
    }
    this.clearFreshnessSchedules();
    const socket = this.socket;
    this.socket = null;
    if (socket && socket.readyState !== WebSocket.CLOSED) {
      socket.removeAllListeners();
      socket.close(1000);
    }
    await this.messageTail.catch(() => undefined);
    this.setStatus('idle', null);
  }

  snapshot(): RuntimeSnapshot {
    return Object.freeze({
      status: this.status,
      ready: this.ready,
      showId: this.showId,
      bindings: this.bindings(),
    });
  }

  bindings(): ReadonlyArray<VisibilityBinding> {
    return Object.freeze(
      [...this.bindingsById.values()]
        .sort(
          (left, right) =>
            targetOrder(left.target) - targetOrder(right.target) ||
            left.controlId.localeCompare(right.controlId)
        )
        .map((binding) => Object.freeze({ ...binding }))
    );
  }

  feedback(bindingId: string): VisibilityFeedbackState {
    const binding = this.bindingsById.get(bindingId);
    if (!binding) return 'unavailable';
    if (this.terminal || this.status === 'failed') return 'failed';
    if (this.status === 'idle' || this.status === 'connecting' || this.status === 'disconnected') {
      return 'disconnected';
    }
    if (!this.ready || this.status !== 'ready') return 'unknown';
    if (this.failedBindings.has(bindingId)) return 'failed';
    const current = this.targetStates.get(binding.target);
    if (!current) return 'unavailable';
    const projection = projectDeviceControl(
      current.state,
      {
        showId: binding.showId,
        target: binding.target,
        controlId: binding.controlId,
      },
      this.now()
    );
    if (!projection.available) return 'unavailable';
    if (projection.buttonState === 'active') return 'active';
    if (projection.buttonState === 'inactive') return 'inactive';
    return 'unknown';
  }

  async execute(mode: VisibilityMode, bindingId: string): Promise<void> {
    const binding = this.bindingsById.get(bindingId);
    if (!binding) throw new Error('Selected control is unavailable');
    if (!this.ready || this.status !== 'ready') {
      throw new Error('OverlayKit device connection is not ready');
    }
    const current = this.targetStates.get(binding.target);
    if (!current) throw new Error('Selected target is unavailable');
    const projection = projectDeviceControl(
      current.state,
      {
        showId: binding.showId,
        target: binding.target,
        controlId: binding.controlId,
      },
      this.now()
    );
    if (!projection.available || projection.status !== 'current') {
      throw new Error('Selected control lacks current server evidence');
    }
    const visible =
      mode === 'show' ? true : mode === 'hide' ? false : projection.buttonState !== 'active';
    const operationId = this.operationId();
    const command = parseDeviceCommandExecute({
      schemaVersion: DEVICE_COMMAND_EXECUTE_VERSION,
      type: DEVICE_COMMAND_EXECUTE_TYPE,
      operationId,
      target: binding.target,
      basedOn: {
        issuerKeyId: current.identity.issuerKeyId,
        sequence: current.identity.sequence,
        sha256: current.identity.sha256,
        productionRevision: current.state.revision,
        catalogGeneration: current.state.catalogGeneration,
      },
      intent: {
        kind: 'component.visibility',
        componentId: binding.componentId,
        visible,
        expectedRevision: current.state.revision,
      },
    } satisfies DeviceCommandExecute);
    this.pendingCommands.set(operationId, {
      bindingId,
      requestSha256: sha256(deviceCommandExecuteBytes(command)),
      intentSha256: sha256(deviceCommandIntentBytes(command)),
    });
    try {
      await this.send(command);
    } catch (error) {
      this.pendingCommands.delete(operationId);
      this.failedBindings.add(bindingId);
      this.notifyFeedback();
      throw error;
    }
  }

  private connect(): void {
    if (this.stopping || this.terminal || !this.config) return;
    this.clearConnectionReadiness();
    this.setStatus('connecting', this.config.insecureLan ? 'Trusted LAN mode' : null);
    let socket: WebSocket;
    try {
      socket = this.createSocket(this.config.endpoint, this.config.bearer);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;

    socket.once('open', () => {
      if (socket !== this.socket || this.stopping) return;
      if (socket.protocol !== DEVICE_SUBPROTOCOL) {
        this.failTerminal('Server selected an unsupported device protocol');
        return;
      }
      this.bootstrappedTargets.clear();
      this.ready = false;
      this.setStatus('open', this.config?.insecureLan ? 'Trusted LAN mode' : null);
      this.notifyFeedback();
    });
    socket.on('message', (data, isBinary) => {
      if (socket !== this.socket || this.stopping) return;
      this.messageTail = this.messageTail
        .then(async () => this.receive(data, isBinary))
        .catch(() => this.failTerminal('Signed device protocol processing failed'));
    });
    socket.once('unexpected-response', (_request: ClientRequest, response: IncomingMessage) => {
      response.resume();
      if (socket !== this.socket || this.stopping) return;
      if (responseIsTerminal(response.statusCode)) {
        this.failTerminal(
          response.statusCode === 401
            ? 'Device authentication failed'
            : 'Device WebSocket upgrade was rejected'
        );
      }
    });
    socket.on('error', () => {
      if (socket === this.socket && !this.stopping && !this.terminal) {
        this.observer.onLog?.('warn', 'Device transport error');
      }
    });
    socket.once('close', (code) => {
      if (socket !== this.socket) return;
      this.socket = null;
      this.clearConnectionReadiness();
      if (this.stopping || this.terminal) return;
      if (closeCodeIsTerminal(code)) {
        this.failTerminal('Device transport closed for a protocol violation');
        return;
      }
      this.setStatus('disconnected', 'Device transport disconnected');
      this.notifyFeedback();
      this.scheduleReconnect();
    });
  }

  private scheduleReconnect(): void {
    if (this.stopping || this.terminal || this.reconnectHandle !== null) return;
    this.setStatus('disconnected', 'Waiting to reconnect');
    const base = Math.min(RECONNECT_BASE_MS * 2 ** this.reconnectAttempt, RECONNECT_MAX_MS);
    const delay = Math.max(1, Math.round(base * (0.75 + this.random() * 0.5)));
    this.reconnectAttempt += 1;
    this.reconnectHandle = this.scheduler.schedule(delay, () => {
      this.reconnectHandle = null;
      this.connect();
    });
  }

  private async receive(data: RawData, isBinary: boolean): Promise<void> {
    if (isBinary) throw new Error('Binary device messages are unsupported');
    let value: unknown;
    try {
      value = JSON.parse(rawDataText(data)) as unknown;
    } catch {
      throw new Error('Device message is not JSON');
    }
    const type = messageType(value);
    if (type === DEVICE_BOOTSTRAP_SNAPSHOT_TYPE) {
      const parsed = await parseDeviceBootstrapSnapshotMessage(value);
      await this.applyFrame(
        'bootstrap',
        parsed.message.target,
        parsed.message.issuerKeyId,
        parsed.message.sequence,
        parsed.message.sha256,
        parsed.payloadBytes,
        parsed.message.signature
      );
      return;
    }
    if (type === DEVICE_STATE_DELTA_TYPE) {
      const parsed = await parseDeviceStateDeltaMessage(value);
      await this.applyFrame(
        'delta',
        parsed.message.target,
        parsed.message.issuerKeyId,
        parsed.message.sequence,
        parsed.message.sha256,
        parsed.payloadBytes,
        parsed.message.signature
      );
      return;
    }
    if (type === DEVICE_READY_TYPE) {
      if (JSON.stringify(value) !== JSON.stringify(buildDeviceReadyMessage())) {
        throw new Error('Device ready message is invalid');
      }
      if (this.bootstrappedTargets.size === 0) {
        throw new Error('Device became ready without an applied bootstrap');
      }
      for (const target of [...this.targetStates.keys()]) {
        if (!this.bootstrappedTargets.has(target)) {
          this.targetStates.delete(target);
          this.cancelFreshness(target);
        }
      }
      this.ready = true;
      this.reconnectAttempt = 0;
      this.rebuildBindings();
      this.setStatus('ready', this.config?.insecureLan ? 'Trusted LAN mode' : null);
      this.notifyFeedback();
      return;
    }
    if (type === DEVICE_COMMAND_RESULT_TYPE || type === DEVICE_COMMAND_REFUSED_TYPE) {
      await this.receiveCommandResponse(value);
      return;
    }
    if (type === 'device.error' && isRecord(value) && value.code === 'not_ready') {
      this.ready = false;
      this.setStatus('open', 'Server is not ready');
      this.notifyFeedback();
      return;
    }
    throw new Error('Device message type is unsupported');
  }

  private async applyFrame(
    mode: 'bootstrap' | 'delta',
    target: ProductionBus,
    issuerKeyId: string,
    sequence: number,
    digest: string,
    payloadBytes: Uint8Array,
    signature: string
  ): Promise<void> {
    const config = this.config;
    if (!config) throw new Error('Device configuration is unavailable');
    if (
      issuerKeyId !== config.trustBundle.issuerKeyId ||
      digest !== sha256(payloadBytes) ||
      !(await config.verifySignature(payloadBytes, signature, issuerKeyId))
    ) {
      throw new Error('Device frame trust verification failed');
    }

    const hints = this.frameAuthorityHints(payloadBytes);
    const authority: DeviceControlFrameAuthorityContext = {
      issuerKeyId: config.trustBundle.issuerKeyId,
      audienceCredentialId: this.audienceCredentialId ?? hints.audienceCredentialId,
      showId: this.showId ?? hints.showId,
      targets: [...new Set([...this.knownTargets, hints.target])],
      controlIds: [...new Set([...this.knownControlIds, ...hints.controlIds])],
      scopes: ['feedback:read', 'component.visibility:write'],
      lastAcceptedSequence: this.lastAcceptedSequence,
      acceptedFrameIdentities: [...this.acceptedIdentities.values()],
    };
    const admitted = await admitDeviceControlFrame(
      payloadBytes,
      signature,
      authority,
      config.verifySignature
    );
    if (
      admitted.frame.mode !== mode ||
      admitted.frame.target !== target ||
      admitted.identity.issuerKeyId !== issuerKeyId ||
      admitted.identity.sequence !== sequence ||
      admitted.identity.sha256 !== digest
    ) {
      throw new Error('Device frame wrapper does not match its signed payload');
    }
    if (this.ready && mode === 'bootstrap') {
      throw new Error('Bootstrap cannot replace a ready connection');
    }
    if (mode === 'delta' && !this.bootstrappedTargets.has(target)) {
      throw new Error('Delta arrived before target bootstrap');
    }

    const current =
      mode === 'bootstrap' && !this.bootstrappedTargets.has(target)
        ? null
        : (this.targetStates.get(target) ?? null);
    let reduced;
    try {
      reduced = await reduceAdmittedDeviceControlFrame(current, admitted);
    } catch (error) {
      await this.sendStateAck(
        mode,
        target,
        issuerKeyId,
        sequence,
        digest,
        'error',
        errorAckCode(error)
      );
      return;
    }

    this.audienceCredentialId ??= hints.audienceCredentialId;
    this.showId ??= hints.showId;
    this.knownTargets.add(target);
    for (const controlId of hints.controlIds) this.knownControlIds.add(controlId);
    this.lastAcceptedSequence = admitted.acceptedSequence;
    this.acceptedIdentities.set(feedbackIdentity(admitted.identity), admitted.identity);
    while (this.acceptedIdentities.size > MAX_ACCEPTED_IDENTITIES) {
      const oldest = this.acceptedIdentities.keys().next().value;
      if (oldest === undefined) break;
      this.acceptedIdentities.delete(oldest);
    }
    this.targetStates.set(target, reduced.state);
    this.bootstrappedTargets.add(target);
    this.scheduleFreshness(target, reduced.state.state.confirmedAt);
    for (const entry of reduced.state.state.controls) {
      this.failedBindings.delete(entry.action.actionId);
    }
    this.rebuildBindings();
    await this.sendStateAck(mode, target, issuerKeyId, sequence, digest, 'applied');
    this.notifyFeedback();
  }

  private frameAuthorityHints(payloadBytes: Uint8Array): {
    audienceCredentialId: string;
    showId: string;
    target: ProductionBus;
    controlIds: string[];
  } {
    const value = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes)
    ) as unknown;
    if (!isRecord(value) || !isRecord(value.frame)) throw new Error('Signed frame is malformed');
    const frame = value.frame;
    const actions = Array.isArray(frame.addedActions) ? frame.addedActions : [];
    const removed = Array.isArray(frame.removedControlIds) ? frame.removedControlIds : [];
    const observations = Array.isArray(frame.observations) ? frame.observations : [];
    const controlIds = [
      ...actions.map((action) =>
        isRecord(action) && isRecord(action.subject) ? action.subject.controlId : null
      ),
      ...removed,
      ...observations.map((observation) =>
        isRecord(observation) && isRecord(observation.subject)
          ? observation.subject.controlId
          : null
      ),
    ].filter((controlId): controlId is string => typeof controlId === 'string');
    return {
      audienceCredentialId:
        typeof value.audienceCredentialId === 'string' ? value.audienceCredentialId : '',
      showId: typeof frame.showId === 'string' ? frame.showId : '',
      target: frame.target as ProductionBus,
      controlIds,
    };
  }

  private async sendStateAck(
    mode: 'bootstrap' | 'delta',
    target: ProductionBus,
    issuerKeyId: string,
    sequence: number,
    digest: string,
    status: 'applied' | 'error',
    errorCode?: DeviceStateAckErrorCode
  ): Promise<void> {
    await this.send({
      schemaVersion: DEVICE_STATE_ACK_VERSION,
      type: DEVICE_STATE_ACK_TYPE,
      mode,
      target,
      issuerKeyId,
      sequence,
      sha256: digest,
      status,
      ...(status === 'error' ? { errorCode: errorCode ?? 'apply_failed' } : {}),
    });
  }

  private async receiveCommandResponse(value: unknown): Promise<void> {
    const config = this.config;
    if (!config) throw new Error('Device configuration is unavailable');
    const parsed = await parseDeviceCommandResponseMessage(value);
    if (
      parsed.message.issuerKeyId !== config.trustBundle.issuerKeyId ||
      !(await config.verifySignature(
        parsed.payloadBytes,
        parsed.message.signature,
        parsed.message.issuerKeyId
      ))
    ) {
      throw new Error('Command response trust verification failed');
    }
    if (parsed.payload.audienceCredentialId !== this.audienceCredentialId) {
      throw new Error('Command response belongs to another credential');
    }
    const pending = this.pendingCommands.get(parsed.payload.operationId);
    if (!pending) return;
    if (
      (parsed.payload.type === DEVICE_COMMAND_RESULT_TYPE &&
        parsed.payload.intentSha256 !== pending.intentSha256) ||
      (parsed.payload.type === DEVICE_COMMAND_REFUSED_TYPE &&
        parsed.payload.requestSha256 !== pending.requestSha256)
    ) {
      throw new Error('Command response does not match its request');
    }
    this.pendingCommands.delete(parsed.payload.operationId);
    if (
      parsed.payload.type === DEVICE_COMMAND_REFUSED_TYPE ||
      parsed.payload.outcome === 'rejected'
    ) {
      this.failedBindings.add(pending.bindingId);
      this.notifyFeedback();
    }
  }

  private rebuildBindings(): void {
    const bindings = new Map<string, VisibilityBinding>();
    for (const current of this.targetStates.values()) {
      for (const entry of current.state.controls) {
        const action: ComponentVisibilityActionDescriptor = entry.action;
        bindings.set(action.actionId, {
          id: action.actionId,
          label: action.label,
          showId: action.subject.showId,
          target: action.subject.target,
          componentId: action.componentId,
          controlId: action.subject.controlId,
        });
      }
    }
    const before = JSON.stringify([...this.bindingsById.values()]);
    const after = JSON.stringify([...bindings.values()]);
    this.bindingsById.clear();
    for (const [id, binding] of bindings) this.bindingsById.set(id, binding);
    if (before !== after) this.observer.onDefinitionsChanged?.();
  }

  private async send(value: unknown): Promise<void> {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error('Device transport is unavailable');
    }
    const payload = JSON.stringify(value);
    await new Promise<void>((resolve, reject) => {
      socket.send(payload, (error) => {
        if (error) reject(new Error('Device transport send failed'));
        else resolve();
      });
    });
  }

  private clearConnectionReadiness(): void {
    this.ready = false;
    this.bootstrappedTargets.clear();
    this.pendingCommands.clear();
  }

  private resetAuthority(): void {
    this.clearFreshnessSchedules();
    this.showId = null;
    this.audienceCredentialId = null;
    this.lastAcceptedSequence = 0;
    this.acceptedIdentities.clear();
    this.targetStates.clear();
    this.bootstrappedTargets.clear();
    this.knownTargets.clear();
    this.knownControlIds.clear();
    this.bindingsById.clear();
    this.failedBindings.clear();
    this.pendingCommands.clear();
    this.observer.onDefinitionsChanged?.();
    this.notifyFeedback();
  }

  private failTerminal(message: string): void {
    if (this.terminal || this.stopping) return;
    this.terminal = true;
    this.ready = false;
    if (this.reconnectHandle !== null) {
      this.scheduler.cancel(this.reconnectHandle);
      this.reconnectHandle = null;
    }
    this.clearFreshnessSchedules();
    const socket = this.socket;
    this.socket = null;
    if (socket && socket.readyState !== WebSocket.CLOSED) {
      socket.removeAllListeners();
      socket.close(1008);
    }
    this.setStatus('failed', message);
    this.notifyFeedback();
    this.observer.onLog?.('error', message);
  }

  private setStatus(status: RuntimeConnectionStatus, message: string | null): void {
    if (this.status === status && message === null) return;
    this.status = status;
    this.observer.onStatusChanged?.(status, message);
  }

  private notifyFeedback(): void {
    this.observer.onFeedbackChanged?.();
  }

  private scheduleFreshness(target: ProductionBus, confirmedAt: number): void {
    this.cancelFreshness(target);
    const expiresAt = confirmedAt + DEFAULT_CONTROL_FEEDBACK_TIMEOUT_MS;
    const delay = Math.max(1, expiresAt - this.now());
    this.freshnessHandles.set(
      target,
      this.scheduler.schedule(delay, () => {
        this.freshnessHandles.delete(target);
        this.notifyFeedback();
      })
    );
  }

  private cancelFreshness(target: ProductionBus): void {
    const handle = this.freshnessHandles.get(target);
    if (handle === undefined) return;
    this.scheduler.cancel(handle);
    this.freshnessHandles.delete(target);
  }

  private clearFreshnessSchedules(): void {
    for (const handle of this.freshnessHandles.values()) this.scheduler.cancel(handle);
    this.freshnessHandles.clear();
  }
}
