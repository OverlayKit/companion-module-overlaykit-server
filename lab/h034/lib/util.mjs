import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export async function sha256File(filePath) {
  return sha256(await readFile(filePath));
}

export function monotonicNs() {
  return process.hrtime.bigint().toString();
}

export function runId() {
  return `h034-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`;
}

export async function ensureDirectory(directory) {
  await mkdir(directory, { recursive: true });
}

export async function writeJson(filePath, value) {
  await ensureDirectory(path.dirname(filePath));
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

export async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

export async function waitFor(predicate, options = {}) {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const intervalMs = options.intervalMs ?? 100;
  const startedAt = Date.now();
  let lastError = null;
  while (Date.now() - startedAt <= timeoutMs) {
    try {
      const result = await predicate();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(options.message ?? `Timed out after ${timeoutMs}ms`, { cause: lastError });
}

export async function command(commandName, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(commandName, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: options.inherit ? 'inherit' : ['ignore', 'pipe', 'pipe'],
    });
    let timedOut = false;
    let stdout = '';
    let stderr = '';
    const timer =
      options.timeoutMs === undefined
        ? null
        : setTimeout(() => {
            timedOut = true;
            child.kill('SIGTERM');
          }, options.timeoutMs);
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (timer !== null) clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`${commandName} timed out after ${options.timeoutMs}ms`));
        return;
      }
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(
          new Error(
            `${commandName} ${args.join(' ')} failed with ${code}\n${stderr || stdout}`.trim()
          )
        );
      }
    });
  });
}

export function exactRuntimeText(text) {
  const values = Object.fromEntries(
    text
      .trim()
      .split('\n')
      .map((line) => {
        const separator = line.indexOf('=');
        return [line.slice(0, separator), line.slice(separator + 1)];
      })
  );
  return values;
}
