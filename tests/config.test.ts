import { describe, expect, it, vi } from 'vitest';
import { ModuleConfigurationError, validateModuleConfig } from '../src/config.js';
import { createDeviceFixture } from './device-fixture.js';

describe('module configuration', () => {
  it('accepts loopback WS and explicit trusted LAN WS', async () => {
    const fixture = await createDeviceFixture();
    await expect(
      validateModuleConfig(
        {
          endpoint: 'ws://127.0.0.1:8080/device',
          allowInsecureLan: false,
          trustBundle: fixture.trustBundleJson,
        },
        { bearer: 'secret-bearer' }
      )
    ).resolves.toMatchObject({ insecureLan: false });
    await expect(
      validateModuleConfig(
        {
          endpoint: 'ws://192.168.1.20:8080/device',
          allowInsecureLan: true,
          trustBundle: fixture.trustBundleJson,
        },
        { bearer: 'secret-bearer' }
      )
    ).resolves.toMatchObject({ insecureLan: true });
  });

  it.each([
    'ws://user:secret@localhost:8080/device',
    'ws://localhost:8080/device?token=secret',
    'ws://localhost:8080/device#fragment',
    'ws://localhost:8080/ws',
    'http://localhost:8080/device',
  ])('rejects ambiguous endpoint %s', async (endpoint) => {
    const fixture = await createDeviceFixture();
    await expect(
      validateModuleConfig(
        {
          endpoint,
          allowInsecureLan: false,
          trustBundle: fixture.trustBundleJson,
        },
        { bearer: 'secret-bearer' }
      )
    ).rejects.toBeInstanceOf(ModuleConfigurationError);
  });

  it('fails closed before creating trust when secrets or LAN opt-in are missing', async () => {
    const fixture = await createDeviceFixture();
    await expect(
      validateModuleConfig(
        {
          endpoint: 'ws://10.0.0.2:8080/device',
          allowInsecureLan: false,
          trustBundle: fixture.trustBundleJson,
        },
        { bearer: 'secret-bearer' }
      )
    ).rejects.toThrow('Trusted LAN');
    await expect(
      validateModuleConfig(
        {
          endpoint: 'wss://overlaykit.example/device',
          allowInsecureLan: false,
          trustBundle: fixture.trustBundleJson,
        },
        { bearer: '' }
      )
    ).rejects.toThrow('bearer');
  });

  it('rejects malformed or substituted trust without logging the bearer', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await expect(
      validateModuleConfig(
        {
          endpoint: 'wss://overlaykit.example/device',
          allowInsecureLan: false,
          trustBundle: '{"schemaVersion":"wrong"}',
        },
        { bearer: 'do-not-log-this-secret' }
      )
    ).rejects.toThrow('Trust Bundle');
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });
});
