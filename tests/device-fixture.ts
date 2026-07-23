import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { WebSocket, WebSocketServer, type RawData } from 'ws';
import {
  projectAuthorizedControlActionCatalog,
  type AuthorizedControlActionCatalog,
} from '@overlaykit/protocol/control-action-catalog';
import {
  DEVICE_BOOTSTRAP_SNAPSHOT_TYPE,
  buildDeviceBootstrapSnapshotMessage,
} from '@overlaykit/protocol/device-bootstrap';
import {
  DEVICE_COMMAND_REFUSED_TYPE,
  DEVICE_COMMAND_REFUSED_VERSION,
  DEVICE_COMMAND_RESULT_TYPE,
  buildDeviceCommandRefusedPayload,
  buildDeviceCommandResponseMessage,
  buildDeviceCommandResultPayload,
  deviceCommandExecuteBytes,
  deviceCommandResponsePayloadBytes,
  parseDeviceCommandExecute,
  type DeviceCommandExecute,
} from '@overlaykit/protocol/device-command';
import {
  DEVICE_CONTROL_FRAME_ENVELOPE_VERSION,
  buildDeviceControlBootstrapFrame,
  buildDeviceControlDeltaFrame,
  deviceControlFramePayloadBytes,
  reduceDeviceControlFrame,
  type DeviceControlFrame,
  type DeviceControlFrameIdentity,
  type DeviceControlFrameState,
  type UnsignedDeviceControlFrameEnvelope,
} from '@overlaykit/protocol/device-control-frame';
import {
  buildDeviceStateDeltaMessage,
  parseDeviceStateAck,
  type DeviceStateAck,
} from '@overlaykit/protocol/device-state-sync';
import { buildDeviceTrustBundle, type DeviceTrustBundle } from '@overlaykit/protocol/device-trust';
import type { DeviceCredentialAuthority } from '@overlaykit/protocol/device-credential';
import type { AuthoritativeServerObservation } from '@overlaykit/protocol/control-feedback';

const SHOW_ID = 'show-1';
const COMPONENT_ID = 'lower-third';
const CONTROL_ID = `${COMPONENT_ID}.visibility`;
const AUDIENCE = 'companion.g1';

export interface IssuedFrame {
  readonly frame: DeviceControlFrame;
  readonly state: DeviceControlFrameState;
  readonly identity: DeviceControlFrameIdentity;
  readonly payloadBytes: Uint8Array;
  readonly signature: string;
}

export interface DeviceFixture {
  readonly trustBundle: DeviceTrustBundle;
  readonly trustBundleJson: string;
  readonly privateKey: KeyObject;
  readonly authority: DeviceCredentialAuthority;
  readonly catalog: AuthorizedControlActionCatalog;
  issueBootstrap(value?: 'active' | 'inactive'): Promise<IssuedFrame>;
  issueDelta(
    base: IssuedFrame,
    value: 'active' | 'inactive',
    includeControl?: boolean
  ): Promise<IssuedFrame>;
}

function digest(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function signature(privateKey: KeyObject, bytes: Uint8Array): string {
  return sign(null, bytes, privateKey).toString('base64url');
}

function rawDataText(data: RawData): string {
  if (Array.isArray(data)) return Buffer.concat(data).toString('utf8');
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString('utf8');
  return data.toString('utf8');
}

function observations(
  catalog: AuthorizedControlActionCatalog,
  value: 'active' | 'inactive',
  revision: number,
  observedAt: number
): AuthoritativeServerObservation[] {
  return catalog.actions.map((action) => ({
    kind: 'server.state.observed',
    subject: { ...action.subject },
    value,
    revision,
    observedAt,
  }));
}

export async function createDeviceFixture(now = 1_000): Promise<DeviceFixture> {
  const pair = generateKeyPairSync('ed25519');
  const publicKeySpki = new Uint8Array(pair.publicKey.export({ format: 'der', type: 'spki' }));
  const trustBundle = await buildDeviceTrustBundle(publicKeySpki);
  const authority: DeviceCredentialAuthority = {
    credentialId: 'companion',
    audienceCredentialId: AUDIENCE,
    generation: 1,
    showId: SHOW_ID,
    targets: ['program'],
    controlIds: [CONTROL_ID],
    scopes: ['feedback:read', 'component.visibility:write'],
    expiresAt: now + 86_400_000,
  };
  const catalog = projectAuthorizedControlActionCatalog(
    {
      showId: SHOW_ID,
      capabilities: [
        {
          kind: 'component.visibility',
          target: 'program',
          componentId: COMPONENT_ID,
          label: 'Lower third',
        },
      ],
    },
    authority
  );
  let sequence = 0;
  let revision = 0;
  let confirmedAt = now;

  async function issue(
    frame: DeviceControlFrame,
    current: DeviceControlFrameState | null,
    base: DeviceControlFrameIdentity | null
  ): Promise<IssuedFrame> {
    sequence += 1;
    const envelope: UnsignedDeviceControlFrameEnvelope = {
      schemaVersion: DEVICE_CONTROL_FRAME_ENVELOPE_VERSION,
      issuerKeyId: trustBundle.issuerKeyId,
      audienceCredentialId: AUDIENCE,
      sequence,
      baseIssuerKeyId: base?.issuerKeyId ?? null,
      baseSequence: base?.sequence ?? null,
      baseSha256: base?.sha256 ?? null,
      frame,
    };
    const payloadBytes = deviceControlFramePayloadBytes(envelope);
    const state = await reduceDeviceControlFrame(current, frame);
    return {
      frame,
      state,
      payloadBytes,
      signature: signature(pair.privateKey, payloadBytes),
      identity: {
        issuerKeyId: trustBundle.issuerKeyId,
        sequence,
        sha256: digest(payloadBytes),
      },
    };
  }

  return {
    trustBundle,
    trustBundleJson: JSON.stringify(trustBundle),
    privateKey: pair.privateKey,
    authority,
    catalog,
    async issueBootstrap(value = 'inactive') {
      revision += 1;
      confirmedAt += 1;
      const frame = await buildDeviceControlBootstrapFrame({
        showId: SHOW_ID,
        target: 'program',
        revision,
        catalogGeneration: 1,
        confirmedAt,
        catalog,
        observations: observations(catalog, value, revision, confirmedAt),
      });
      return issue(frame, null, null);
    },
    async issueDelta(base, value, includeControl = true) {
      revision += 1;
      confirmedAt += 1;
      const nextCatalog: AuthorizedControlActionCatalog = includeControl
        ? catalog
        : {
            schemaVersion: catalog.schemaVersion,
            showId: catalog.showId,
            actions: [],
          };
      const frame = await buildDeviceControlDeltaFrame(base.state, {
        showId: SHOW_ID,
        target: 'program',
        revision,
        catalogGeneration: includeControl ? 1 : 2,
        confirmedAt,
        catalog: nextCatalog,
        observations: observations(nextCatalog, value, revision, confirmedAt),
      });
      return issue(frame, base.state, base.identity);
    },
  };
}

export class SignedDeviceServer {
  readonly server = new WebSocketServer({
    host: '127.0.0.1',
    port: 0,
    path: '/device',
    handleProtocols: (protocols) =>
      protocols.has('overlaykit.device.v1') ? 'overlaykit.device.v1' : false,
  });
  readonly commands: DeviceCommandExecute[] = [];
  readonly acknowledgements: DeviceStateAck[] = [];
  authorization: string | undefined;
  private socket: WebSocket | null = null;
  private current: IssuedFrame | null = null;
  private commandQueue: DeviceCommandExecute[] = [];
  private commandWaiters: Array<(command: DeviceCommandExecute) => void> = [];
  private ackWaiters: Array<(acknowledgement: DeviceStateAck) => void> = [];

  constructor(readonly fixture: DeviceFixture) {}

  async start(): Promise<string> {
    if (!this.server.address()) await once(this.server, 'listening');
    this.server.on('connection', (socket, request) => {
      this.socket = socket;
      this.authorization = request.headers.authorization;
      socket.on('message', (data, isBinary) => {
        if (isBinary) return;
        const value = JSON.parse(rawDataText(data)) as unknown;
        if (
          value &&
          typeof value === 'object' &&
          'type' in value &&
          value.type === 'device.state.ack'
        ) {
          const acknowledgement = parseDeviceStateAck(value);
          this.acknowledgements.push(acknowledgement);
          this.ackWaiters.shift()?.(acknowledgement);
          return;
        }
        const command = parseDeviceCommandExecute(value);
        this.commands.push(command);
        const waiter = this.commandWaiters.shift();
        if (waiter) waiter(command);
        else this.commandQueue.push(command);
      });
    });
    const address = this.server.address() as AddressInfo;
    return `ws://127.0.0.1:${address.port}/device`;
  }

  async waitForConnection(): Promise<void> {
    if (this.socket?.readyState === WebSocket.OPEN) return;
    await once(this.server, 'connection');
  }

  async bootstrap(value: 'active' | 'inactive' = 'inactive'): Promise<IssuedFrame> {
    const issued = await this.sendBootstrap(value);
    await this.sendReady();
    return issued;
  }

  async sendBootstrap(value: 'active' | 'inactive' = 'inactive'): Promise<IssuedFrame> {
    const issued = await this.fixture.issueBootstrap(value);
    this.current = issued;
    const message = await buildDeviceBootstrapSnapshotMessage({
      target: 'program',
      issuerKeyId: issued.identity.issuerKeyId,
      sequence: issued.identity.sequence,
      sha256: issued.identity.sha256,
      payloadBytes: issued.payloadBytes,
      signature: issued.signature,
    });
    const acknowledgement = this.waitForAck();
    await this.send(message);
    this.assertAppliedAck(await acknowledgement, 'bootstrap', issued);
    return issued;
  }

  async sendReady(): Promise<void> {
    await this.send({ schemaVersion: 'overlaykit-device-ready/v1', type: 'device.ready' });
  }

  async delta(value: 'active' | 'inactive', includeControl = true): Promise<IssuedFrame> {
    if (!this.current) throw new Error('Bootstrap is required');
    const issued = await this.fixture.issueDelta(this.current, value, includeControl);
    this.current = issued;
    const message = await buildDeviceStateDeltaMessage({
      target: 'program',
      issuerKeyId: issued.identity.issuerKeyId,
      sequence: issued.identity.sequence,
      sha256: issued.identity.sha256,
      payloadBytes: issued.payloadBytes,
      signature: issued.signature,
    });
    const acknowledgement = this.waitForAck();
    await this.send(message);
    this.assertAppliedAck(await acknowledgement, 'delta', issued);
    return issued;
  }

  async waitForCommand(): Promise<DeviceCommandExecute> {
    const queued = this.commandQueue.shift();
    if (queued) return queued;
    return await new Promise((resolve) => this.commandWaiters.push(resolve));
  }

  async respondApplied(command: DeviceCommandExecute): Promise<void> {
    const payload = buildDeviceCommandResultPayload({
      schemaVersion: 'overlaykit-device-command-result/v1',
      type: DEVICE_COMMAND_RESULT_TYPE,
      issuerKeyId: this.fixture.trustBundle.issuerKeyId,
      audienceCredentialId: AUDIENCE,
      operationId: command.operationId,
      intentSha256: digest(
        new TextEncoder().encode(
          JSON.stringify({
            schemaVersion: 'overlaykit-device-command-intent/v1',
            target: command.target,
            kind: command.intent.kind,
            componentId: command.intent.componentId,
            visible: command.intent.visible,
            expectedRevision: command.intent.expectedRevision,
          })
        )
      ),
      outcome: 'applied',
      resultCode: 'APPLIED',
      commandSequence: 1,
      expectedRevision: command.intent.expectedRevision,
      previousRevision: command.intent.expectedRevision,
      resultingRevision: command.intent.expectedRevision + 1,
      replayed: false,
    });
    const bytes = deviceCommandResponsePayloadBytes(payload);
    const message = await buildDeviceCommandResponseMessage({
      payload,
      signature: signature(this.fixture.privateKey, bytes),
    });
    await this.send(message);
  }

  async respondRefused(command: DeviceCommandExecute): Promise<void> {
    const payload = buildDeviceCommandRefusedPayload({
      schemaVersion: DEVICE_COMMAND_REFUSED_VERSION,
      type: DEVICE_COMMAND_REFUSED_TYPE,
      issuerKeyId: this.fixture.trustBundle.issuerKeyId,
      audienceCredentialId: AUDIENCE,
      operationId: command.operationId,
      requestSha256: digest(deviceCommandExecuteBytes(command)),
      reason: 'not_authorized',
    });
    const bytes = deviceCommandResponsePayloadBytes(payload);
    const message = await buildDeviceCommandResponseMessage({
      payload,
      signature: signature(this.fixture.privateKey, bytes),
    });
    await this.send(message);
  }

  async sendInvalidSignatureBootstrap(): Promise<void> {
    const issued = await this.fixture.issueBootstrap();
    const message = await buildDeviceBootstrapSnapshotMessage({
      target: 'program',
      issuerKeyId: issued.identity.issuerKeyId,
      sequence: issued.identity.sequence,
      sha256: issued.identity.sha256,
      payloadBytes: issued.payloadBytes,
      signature: 'A'.repeat(86),
    });
    if (message.type !== DEVICE_BOOTSTRAP_SNAPSHOT_TYPE) throw new Error('Invalid fixture');
    await this.send(message);
  }

  disconnect(): void {
    this.socket?.close(1001);
  }

  async close(): Promise<void> {
    this.socket?.terminate();
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  private async send(value: unknown): Promise<void> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('Fixture socket is unavailable');
    }
    await new Promise<void>((resolve, reject) => {
      this.socket!.send(JSON.stringify(value), (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  private async waitForAck(): Promise<DeviceStateAck> {
    return await new Promise<DeviceStateAck>((resolve) => this.ackWaiters.push(resolve));
  }

  private assertAppliedAck(
    acknowledgement: DeviceStateAck,
    mode: 'bootstrap' | 'delta',
    issued: IssuedFrame
  ): void {
    if (
      acknowledgement.status !== 'applied' ||
      acknowledgement.mode !== mode ||
      acknowledgement.target !== 'program' ||
      acknowledgement.issuerKeyId !== issued.identity.issuerKeyId ||
      acknowledgement.sequence !== issued.identity.sequence ||
      acknowledgement.sha256 !== issued.identity.sha256
    ) {
      throw new Error('Module acknowledgement does not match the issued frame');
    }
  }
}

export async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt >= timeoutMs) throw new Error('Timed out waiting for condition');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
