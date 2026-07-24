import net from 'node:net';
import { monotonicNs } from './util.mjs';

function parseLine(line) {
  const firstSpace = line.indexOf(' ');
  const command = firstSpace === -1 ? line : line.slice(0, firstSpace);
  const values = {};
  const expression = /([A-Z_]+)=(?:"([^"]*)"|([^\s]+))/gu;
  for (const match of line.matchAll(expression)) values[match[1]] = match[2] ?? match[3];
  if (values.TEXT) values.TEXT = Buffer.from(values.TEXT, 'base64').toString('utf8');
  return { command, values, raw: line };
}

export class SatelliteObserver {
  constructor(port, heartbeatMs = 2_000) {
    this.port = port;
    this.heartbeatMs = heartbeatMs;
    this.socket = null;
    this.heartbeat = null;
    this.buffer = '';
    this.lines = [];
    this.waiters = new Set();
  }

  async connect() {
    await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port: this.port });
      this.socket = socket;
      socket.setEncoding('utf8');
      socket.once('connect', resolve);
      socket.once('error', reject);
      socket.on('data', (chunk) => this.receive(chunk));
      socket.on('close', () => this.stopHeartbeat());
    });
    await this.waitFor((line) => line.command === 'BEGIN', 10_000);
    this.heartbeat = setInterval(() => {
      if (this.socket?.writable) this.socket.write(`PING ID="${Date.now()}"\n`);
    }, this.heartbeatMs);
  }

  receive(chunk) {
    this.buffer += chunk;
    let separator = this.buffer.indexOf('\n');
    while (separator !== -1) {
      const raw = this.buffer.slice(0, separator).replace(/\r$/u, '');
      this.buffer = this.buffer.slice(separator + 1);
      const line = {
        ...parseLine(raw),
        wallClock: new Date().toISOString(),
        monotonicNs: monotonicNs(),
      };
      this.lines.push(line);
      for (const waiter of this.waiters) waiter(line);
      separator = this.buffer.indexOf('\n');
    }
  }

  async subscribe(subId, location) {
    this.socket.write(`ADD-SUB SUBID="${subId}" LOCATION="${location}" TEXT=1 COLORS=hex\n`);
    await this.waitFor((line) => line.command === 'ADD-SUB' && line.values.SUBID === subId, 10_000);
    return this.waitForState(subId, undefined, 10_000);
  }

  async waitForState(subId, text, timeoutMs, afterMonotonicNs = '0') {
    return this.waitFor(
      (line) =>
        line.command === 'SUB-STATE' &&
        line.values.SUBID === subId &&
        (text === undefined || line.values.TEXT === text) &&
        BigInt(line.monotonicNs) > BigInt(afterMonotonicNs),
      timeoutMs
    );
  }

  waitFor(predicate, timeoutMs) {
    const prior = [...this.lines].reverse().find(predicate);
    if (prior) return Promise.resolve(prior);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(onLine);
        reject(new Error(`Satellite observation timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      const onLine = (line) => {
        if (!predicate(line)) return;
        clearTimeout(timer);
        this.waiters.delete(onLine);
        resolve(line);
      };
      this.waiters.add(onLine);
    });
  }

  close() {
    this.stopHeartbeat();
    this.socket?.destroy();
    this.socket = null;
  }

  stopHeartbeat() {
    if (this.heartbeat !== null) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }
}
