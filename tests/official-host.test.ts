import type {
  HostActionDefinition,
  HostFeedbackDefinition,
  HostFeedbackValue,
  ModuleHostContext,
} from '@companion-module/host';
import { InstanceStatus } from '@companion-module/host';
import { describe, expect, it, vi } from 'vitest';
import { InstanceWrapper } from '@companion-module/host';
import type { ModuleSchema } from '../src/main.js';
import type { ModuleConfig, ModuleSecrets } from '../src/config.js';
import { createDeviceFixture, SignedDeviceServer, waitFor } from './device-fixture.js';

function createHost() {
  let actions: HostActionDefinition[] = [];
  let feedbacks: HostFeedbackDefinition[] = [];
  const statuses: Array<{ status: InstanceStatus; message: string | null }> = [];
  const feedbackValues: HostFeedbackValue[] = [];
  const host: ModuleHostContext<ModuleConfig, ModuleSecrets> = {
    setStatus(status, message) {
      statuses.push({ status, message });
    },
    setActionDefinitions(value) {
      actions = value;
    },
    setFeedbackDefinitions(value) {
      feedbacks = value;
    },
    setVariableDefinitions: vi.fn(),
    setPresetDefinitions: vi.fn(),
    setVariableValues: vi.fn(),
    updateFeedbackValues(values) {
      feedbackValues.push(...values);
    },
    saveConfig: vi.fn(),
    sendOSC: vi.fn(),
    recordAction: vi.fn(),
    setCustomVariable: vi.fn(),
    sharedUdpSocketJoin: vi.fn(async () => 'handle'),
    sharedUdpSocketLeave: vi.fn(async () => undefined),
    sharedUdpSocketSend: vi.fn(async () => undefined),
  };
  return {
    host,
    actions: () => actions,
    feedbacks: () => feedbacks,
    statuses,
    feedbackValues,
  };
}

describe('official Companion API 2.0 host', () => {
  it('loads lifecycle and definitions, executes an action, and evaluates signed feedback', async () => {
    const compiledModule = (await import(
      new URL('../dist/main.js', import.meta.url).href
    )) as typeof import('../src/main.js');
    const ModuleInstance = compiledModule.default;
    const { UpgradeScripts } = compiledModule;
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const captured = createHost();
    const wrapper = new InstanceWrapper<ModuleSchema>(
      'overlaykit-test',
      captured.host,
      ModuleInstance,
      UpgradeScripts
    );

    await wrapper.init({
      label: 'OverlayKit test',
      isFirstInit: false,
      config: {
        endpoint,
        allowInsecureLan: false,
        trustBundle: fixture.trustBundleJson,
      },
      secrets: { bearer: 'official-host-token' },
      lastUpgradeIndex: -1,
    });
    await server.waitForConnection();
    await server.bootstrap('inactive');
    await waitFor(() => captured.statuses.some(({ status }) => status === InstanceStatus.Ok));

    expect(captured.actions().map(({ id }) => id)).toEqual([
      'visibility.show',
      'visibility.hide',
      'visibility.toggle',
    ]);
    expect(captured.feedbacks().map(({ id }) => id)).toEqual(['visibility.state']);
    const bindingOption = captured.actions()[0]?.options[0];
    if (!bindingOption || bindingOption.type !== 'dropdown') {
      throw new Error('Official host did not expose a binding dropdown');
    }
    const binding = String(bindingOption.choices[0]?.id);
    const feedbackBindingOption = captured.feedbacks()[0]?.options[0];
    if (!feedbackBindingOption || feedbackBindingOption.type !== 'dropdown') {
      throw new Error('Official host did not expose a feedback binding dropdown');
    }
    expect(feedbackBindingOption.choices.map(({ id }) => id)).toContain(
      '__overlaykit_unavailable__'
    );

    await wrapper.updateFeedbacks({
      visibility: {
        id: 'visibility',
        feedbackId: 'visibility.state',
        controlId: 'button-1',
        options: { binding },
      },
    });
    await waitFor(() =>
      captured.feedbackValues.some(({ value }) =>
        Boolean(value && typeof value === 'object' && 'text' in value && value.text === 'INACTIVE')
      )
    );

    const result = await wrapper.executeAction(
      {
        id: 'show-action',
        actionId: 'visibility.show',
        controlId: 'button-1',
        options: { binding },
      },
      undefined
    );
    expect(result).toEqual({ success: true, errorMessage: undefined });
    const command = await server.waitForCommand();
    expect(command.intent).toMatchObject({
      kind: 'component.visibility',
      componentId: 'lower-third',
      visible: true,
    });

    await server.respondApplied(command);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(captured.feedbackValues.at(-1)?.value).toMatchObject({ text: 'INACTIVE' });

    await server.delta('active');
    await waitFor(() =>
      captured.feedbackValues.some(({ value }) =>
        Boolean(value && typeof value === 'object' && 'text' in value && value.text === 'ACTIVE')
      )
    );

    await wrapper.destroy();
    await server.close();
  });
});
