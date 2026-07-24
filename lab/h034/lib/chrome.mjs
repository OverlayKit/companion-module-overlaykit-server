import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { access, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { waitFor } from './util.mjs';

function cdpClient(url) {
  const socket = new WebSocket(url);
  const pending = new Map();
  let sequence = 0;
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data));
    if (message.id === undefined) return;
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
  });
  socket.addEventListener('close', () => {
    for (const request of pending.values()) {
      request.reject(new Error('Chrome DevTools connection closed'));
    }
    pending.clear();
  });
  return {
    socket,
    async open() {
      if (socket.readyState === WebSocket.OPEN) return;
      await once(socket, 'open');
    },
    send(method, params = {}) {
      sequence += 1;
      const id = sequence;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    close() {
      socket.close();
    },
  };
}

function processGroupRunning(pid) {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    if (error?.code === 'EPERM' && process.platform === 'darwin') return false;
    throw error;
  }
}

async function waitForChromeExit(child, grouped, timeoutMs) {
  const startedAt = Date.now();
  while (Date.now() - startedAt <= timeoutMs) {
    const running = grouped
      ? processGroupRunning(child.pid)
      : child.exitCode === null && child.signalCode === null;
    if (!running) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

function signalChrome(child, grouped, signal) {
  try {
    if (grouped) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
  }
}

export async function stopChrome(child, timeoutMs = 2_000) {
  const grouped = process.platform !== 'win32' && Number.isInteger(child.pid);
  if (!grouped && (child.exitCode !== null || child.signalCode !== null)) return;
  signalChrome(child, grouped, 'SIGTERM');
  if (await waitForChromeExit(child, grouped, timeoutMs)) return;
  signalChrome(child, grouped, 'SIGKILL');
  if (!(await waitForChromeExit(child, grouped, timeoutMs))) {
    throw new Error('Chrome process group did not exit after SIGKILL');
  }
}

export async function removeChromeProfile(profile, dependencies = {}) {
  const remove = dependencies.remove ?? rm;
  const inspect = dependencies.access ?? access;
  const settleMs = dependencies.settleMs ?? 250;
  await remove(profile, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 100,
  });
  await new Promise((resolve) => setTimeout(resolve, settleMs));
  try {
    await inspect(profile);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new Error(`Chrome profile reappeared after cleanup: ${profile}`);
}

export async function captureChromePage({
  executable,
  profile,
  url,
  output,
  readySelector,
  width = 960,
  height = 640,
  timeoutMs = 20_000,
}) {
  const child = spawn(
    executable,
    [
      '--headless=new',
      '--disable-gpu',
      '--hide-scrollbars',
      '--no-first-run',
      '--no-sandbox',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      `--window-size=${width},${height}`,
      url,
    ],
    {
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'ignore', 'pipe'],
    }
  );
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });
  const activePortPath = path.join(profile, 'DevToolsActivePort');
  let client = null;
  try {
    const activePort = await waitFor(
      async () => {
        if (child.exitCode !== null) {
          throw new Error(`Chrome exited before DevTools was ready: ${stderr.trim()}`);
        }
        try {
          return await readFile(activePortPath, 'utf8');
        } catch {
          return null;
        }
      },
      { timeoutMs, message: 'Chrome DevTools endpoint did not become ready' }
    );
    const port = activePort.trim().split('\n')[0];
    const targets = await waitFor(
      async () => {
        const response = await fetch(`http://127.0.0.1:${port}/json/list`);
        if (!response.ok) return null;
        const current = await response.json();
        return current.find((target) => target.type === 'page' && target.url === url) ?? null;
      },
      { timeoutMs, message: 'Chrome did not expose the requested page target' }
    );
    client = cdpClient(targets.webSocketDebuggerUrl);
    await client.open();
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('Emulation.setDeviceMetricsOverride', {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await waitFor(
      async () => {
        const result = await client.send('Runtime.evaluate', {
          expression: `document.querySelector(${JSON.stringify(readySelector)}) !== null`,
          returnByValue: true,
        });
        return result.result?.value === true;
      },
      { timeoutMs, message: `Chrome page did not render ${readySelector}` }
    );
    const screenshot = await client.send('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true,
      captureBeyondViewport: false,
    });
    await writeFile(output, Buffer.from(screenshot.data, 'base64'), { mode: 0o600 });
  } finally {
    client?.close();
    await stopChrome(child);
    await removeChromeProfile(profile);
  }
}
