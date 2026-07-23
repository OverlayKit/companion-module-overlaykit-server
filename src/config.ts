import type { SomeCompanionConfigField } from '@companion-module/base';
import {
  createDeviceTrustSignatureVerifier,
  parseDeviceTrustBundle,
  type DeviceTrustBundle,
  type DeviceTrustSignatureVerifier,
} from '@overlaykit/protocol/device-trust';

const MAX_ENDPOINT_LENGTH = 2_048;
const MAX_BEARER_LENGTH = 1_024;
const MAX_TRUST_BUNDLE_LENGTH = 16_384;

export interface ModuleConfig {
  readonly [key: string]: string | boolean;
  readonly endpoint: string;
  readonly allowInsecureLan: boolean;
  readonly trustBundle: string;
}

export interface ModuleSecrets {
  readonly [key: string]: string;
  readonly bearer: string;
}

export interface ValidatedModuleConfig {
  readonly endpoint: string;
  readonly insecureLan: boolean;
  readonly trustBundle: DeviceTrustBundle;
  readonly verifySignature: DeviceTrustSignatureVerifier;
  readonly bearer: string;
}

export class ModuleConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ModuleConfigurationError';
  }
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === 'localhost' || normalized === '[::1]' || normalized === '::1') return true;
  const octets = normalized.split('.');
  return (
    octets.length === 4 &&
    octets[0] === '127' &&
    octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255)
  );
}

function parseEndpoint(
  value: unknown,
  allowInsecureLan: boolean
): {
  endpoint: string;
  insecureLan: boolean;
} {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_ENDPOINT_LENGTH ||
    value !== value.trim()
  ) {
    throw new ModuleConfigurationError('Device endpoint is required');
  }

  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new ModuleConfigurationError('Device endpoint is invalid');
  }
  if (
    (endpoint.protocol !== 'ws:' && endpoint.protocol !== 'wss:') ||
    endpoint.username !== '' ||
    endpoint.password !== '' ||
    endpoint.search !== '' ||
    endpoint.hash !== '' ||
    endpoint.pathname !== '/device' ||
    endpoint.hostname === ''
  ) {
    throw new ModuleConfigurationError(
      'Device endpoint must be an unambiguous ws(s) URL ending in /device'
    );
  }

  const insecureLan = endpoint.protocol === 'ws:' && !isLoopback(endpoint.hostname);
  if (insecureLan && allowInsecureLan !== true) {
    throw new ModuleConfigurationError(
      'Plain WS outside loopback requires explicit Trusted LAN opt-in'
    );
  }
  return { endpoint: endpoint.toString(), insecureLan };
}

function parseBearer(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_BEARER_LENGTH ||
    value !== value.trim() ||
    /\s/u.test(value)
  ) {
    throw new ModuleConfigurationError('Device bearer is required');
  }
  return value;
}

async function parseTrust(value: unknown): Promise<{
  trustBundle: DeviceTrustBundle;
  verifySignature: DeviceTrustSignatureVerifier;
}> {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_TRUST_BUNDLE_LENGTH) {
    throw new ModuleConfigurationError('Device Trust Bundle is required');
  }
  let candidate: unknown;
  try {
    candidate = JSON.parse(value) as unknown;
  } catch {
    throw new ModuleConfigurationError('Device Trust Bundle JSON is invalid');
  }
  try {
    const parsed = await parseDeviceTrustBundle(candidate);
    const verifySignature = await createDeviceTrustSignatureVerifier(parsed.bundle);
    return { trustBundle: parsed.bundle, verifySignature };
  } catch {
    throw new ModuleConfigurationError('Device Trust Bundle is invalid');
  }
}

export async function validateModuleConfig(
  config: ModuleConfig,
  secrets: ModuleSecrets
): Promise<ValidatedModuleConfig> {
  const allowInsecureLan = config?.allowInsecureLan === true;
  const endpoint = parseEndpoint(config?.endpoint, allowInsecureLan);
  const bearer = parseBearer(secrets?.bearer);
  const trust = await parseTrust(config?.trustBundle);
  return Object.freeze({
    endpoint: endpoint.endpoint,
    insecureLan: endpoint.insecureLan,
    bearer,
    ...trust,
  });
}

export function getConfigFields(): SomeCompanionConfigField[] {
  return [
    {
      id: 'endpoint',
      type: 'textinput',
      label: 'Device WebSocket URL',
      width: 12,
      default: 'ws://127.0.0.1:8080/device',
    },
    {
      id: 'allowInsecureLan',
      type: 'checkbox',
      label: 'Allow plain WS on a trusted non-loopback LAN',
      width: 12,
      default: false,
    },
    {
      id: 'bearer',
      type: 'secret-text',
      label: 'Device bearer',
      width: 12,
      minLength: 1,
    },
    {
      id: 'trustBundle',
      type: 'textinput',
      label: 'Device Trust Bundle JSON',
      width: 12,
      multiline: true,
      minLength: 1,
    },
  ];
}
