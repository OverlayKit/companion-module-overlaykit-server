import { EventEmitter } from 'node:events';
import WebSocket from 'ws';
import { describe, expect, it, vi } from 'vitest';
import { OverlayKitControlRuntime } from '../src/runtime.js';
import { createDeviceFixture, SignedDeviceServer, waitFor } from './device-fixture.js';

function moduleConfig(endpoint: string, trustBundle: string) {
  return {
    endpoint,
    allowInsecureLan: false,
    trustBundle,
  };
}

describe('OverlayKit control runtime', () => {
  it('applies signed bootstrap, preserves state through command result, and changes on delta', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.bootstrap('inactive');
    await waitFor(() => runtime.snapshot().status === 'ready');
    const binding = runtime.bindings()[0];

    expect(server.authorization).toBe('Bearer device-token');
    expect(runtime.feedback(binding.id)).toBe('inactive');

    await runtime.execute('show', binding.id);
    const command = await server.waitForCommand();
    expect(command.intent.visible).toBe(true);
    expect(runtime.feedback(binding.id)).toBe('inactive');

    await server.respondApplied(command);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(runtime.feedback(binding.id)).toBe('inactive');

    await server.delta('active');
    await waitFor(() => runtime.feedback(binding.id) === 'active');

    await runtime.stop();
    await server.close();
  });

  it('derives hide and toggle commands from the latest signed visibility evidence', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.bootstrap('active');
    await waitFor(() => runtime.snapshot().status === 'ready');
    const binding = runtime.bindings()[0];

    await runtime.execute('hide', binding.id);
    const hide = await server.waitForCommand();
    expect(hide.intent.visible).toBe(false);
    await server.respondApplied(hide);
    await server.delta('inactive');

    await runtime.execute('toggle', binding.id);
    const toggle = await server.waitForCommand();
    expect(toggle.intent.visible).toBe(true);

    await runtime.stop();
    await server.close();
  });

  it('stays not ready until an exact bootstrap acknowledgement is followed by device.ready', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.sendBootstrap('active');
    await waitFor(() => runtime.bindings().length === 1);
    const binding = runtime.bindings()[0];

    expect(runtime.snapshot()).toMatchObject({ status: 'open', ready: false, showId: 'show-1' });
    expect(runtime.feedback(binding.id)).toBe('unknown');
    expect(server.acknowledgements).toHaveLength(1);

    await server.sendReady();
    await waitFor(() => runtime.snapshot().status === 'ready');
    expect(runtime.feedback(binding.id)).toBe('active');

    await runtime.stop();
    await server.close();
  });

  it('closes terminally when device.ready arrives before signed bootstrap evidence', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.sendReady();
    await waitFor(() => runtime.snapshot().status === 'failed');

    expect(runtime.snapshot()).toMatchObject({ ready: false, showId: null, bindings: [] });

    await runtime.stop();
    await server.close();
  });

  it('projects unknown after the three-second evidence window', async () => {
    let now = 10_001;
    const feedbackChanged = vi.fn();
    const scheduled: Array<{ delay: number; task: () => void }> = [];
    const fixture = await createDeviceFixture(10_000);
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime(
      { onFeedbackChanged: feedbackChanged },
      {
        now: () => now,
        scheduler: {
          schedule(delay, task) {
            const handle = { delay, task };
            scheduled.push(handle);
            return handle;
          },
          cancel: vi.fn(),
        },
      }
    );
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.bootstrap('active');
    await waitFor(() => runtime.snapshot().status === 'ready');
    const binding = runtime.bindings()[0];
    expect(runtime.feedback(binding.id)).toBe('active');
    expect(scheduled).toHaveLength(1);
    expect(scheduled[0]?.delay).toBe(3_000);

    const callsBeforeExpiry = feedbackChanged.mock.calls.length;
    now += 3_000;
    scheduled[0]?.task();
    expect(runtime.feedback(binding.id)).toBe('unknown');
    expect(feedbackChanged.mock.calls.length).toBeGreaterThan(callsBeforeExpiry);

    await runtime.stop();
    await server.close();
  });

  it('projects failed after a signed command refusal and clears only on newer signed state', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.bootstrap('inactive');
    await waitFor(() => runtime.snapshot().status === 'ready');
    const binding = runtime.bindings()[0];

    await runtime.execute('show', binding.id);
    const command = await server.waitForCommand();
    await server.respondRefused(command);
    await waitFor(() => runtime.feedback(binding.id) === 'failed');

    await server.delta('inactive');
    await waitFor(() => runtime.feedback(binding.id) === 'inactive');

    await runtime.stop();
    await server.close();
  });

  it('keeps the binding but projects disconnected after transport loss', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.bootstrap('active');
    await waitFor(() => runtime.snapshot().status === 'ready');
    const binding = runtime.bindings()[0];

    server.disconnect();
    await waitFor(() => runtime.snapshot().status === 'disconnected');
    expect(runtime.feedback(binding.id)).toBe('disconnected');
    expect(runtime.bindings()).toHaveLength(1);

    await runtime.stop();
    await server.close();
  });

  it('projects unavailable after a signed catalog removal', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const runtime = new OverlayKitControlRuntime();
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.bootstrap('active');
    await waitFor(() => runtime.snapshot().status === 'ready');
    const binding = runtime.bindings()[0];

    await server.delta('inactive', false);
    await waitFor(() => runtime.bindings().length === 0);
    expect(runtime.feedback(binding.id)).toBe('unavailable');

    await runtime.stop();
    await server.close();
  });

  it('fails terminally on a substituted signature and does not reconnect', async () => {
    const fixture = await createDeviceFixture(Date.now());
    const server = new SignedDeviceServer(fixture);
    const endpoint = await server.start();
    const scheduled = vi.fn();
    const onLog = vi.fn();
    const runtime = new OverlayKitControlRuntime(
      { onLog },
      {
        scheduler: {
          schedule: scheduled,
          cancel: vi.fn(),
        },
      }
    );
    await runtime.start(moduleConfig(endpoint, fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    await server.waitForConnection();
    await server.sendInvalidSignatureBootstrap();
    await waitFor(() => runtime.snapshot().status === 'failed');

    expect(scheduled).not.toHaveBeenCalled();
    expect(onLog).toHaveBeenCalledWith(
      'error',
      'Signed device protocol processing failed: Device frame trust verification failed'
    );
    await runtime.stop();
    await server.close();
  });

  it('uses bounded deterministic jitter for retryable disconnects', async () => {
    class FakeSocket extends EventEmitter {
      readyState = WebSocket.CONNECTING;
      protocol = '';
      close = vi.fn();
      send = vi.fn();
    }
    const fixture = await createDeviceFixture();
    const socket = new FakeSocket();
    const scheduled: number[] = [];
    const runtime = new OverlayKitControlRuntime(
      {},
      {
        createSocket: () => socket as unknown as WebSocket,
        random: () => 0,
        scheduler: {
          schedule(delay, _task) {
            scheduled.push(delay);
            return delay;
          },
          cancel: vi.fn(),
        },
      }
    );
    await runtime.start(moduleConfig('ws://127.0.0.1:8080/device', fixture.trustBundleJson), {
      bearer: 'device-token',
    });
    socket.emit('close', 1006);

    expect(scheduled).toEqual([375]);
    expect(runtime.snapshot().status).toBe('disconnected');
    await runtime.stop();
  });

  it('keeps an HTTP 401 upgrade rejection terminal until explicit restart', async () => {
    class FakeSocket extends EventEmitter {
      readyState = WebSocket.CONNECTING;
      protocol = '';
      close = vi.fn();
      send = vi.fn();
    }
    const fixture = await createDeviceFixture();
    const socket = new FakeSocket();
    const scheduled = vi.fn();
    const runtime = new OverlayKitControlRuntime(
      {},
      {
        createSocket: () => socket as unknown as WebSocket,
        scheduler: {
          schedule: scheduled,
          cancel: vi.fn(),
        },
      }
    );
    await runtime.start(moduleConfig('ws://127.0.0.1:8080/device', fixture.trustBundleJson), {
      bearer: 'device-token',
    });

    socket.emit('unexpected-response', {}, { statusCode: 401, resume: vi.fn() });

    expect(runtime.snapshot()).toMatchObject({ status: 'failed', ready: false });
    expect(scheduled).not.toHaveBeenCalled();
    await runtime.stop();
  });

  it('starts without persisted operational authority', () => {
    const runtime = new OverlayKitControlRuntime();
    expect(runtime.snapshot()).toMatchObject({
      status: 'idle',
      ready: false,
      showId: null,
      bindings: [],
    });
  });
});
