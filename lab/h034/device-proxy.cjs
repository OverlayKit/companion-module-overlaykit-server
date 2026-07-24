'use strict';

const { appendFileSync, mkdirSync } = require('node:fs');
const http = require('node:http');
const { WebSocket, WebSocketServer } = require('ws');
const {
  commandCorrelation,
  parsedMessage,
  responseCorrelation,
  sha256,
} = require('./lib/proxy-evidence.cjs');

const LISTEN_PORT = 8081;
const CONTROL_PORT = 9090;
const UPSTREAM = 'ws://127.0.0.1:8080/device';
const EVENTS_PATH = '/evidence/proxy-events.jsonl';
const VALID_MODES = new Set(['pass', 'delay-state', 'offline']);

let eventSequence = 0;
let mode = 'pass';
let delayMs = 3500;
let downstream = null;

mkdirSync('/evidence', { recursive: true });

function record(kind, details = {}) {
  const entry = {
    schemaVersion: 'overlaykit-h034-proxy-event/v1',
    eventSequence: ++eventSequence,
    wallClock: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    kind,
    mode,
    ...details,
  };
  appendFileSync(EVENTS_PATH, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600 });
}

function messageDetails(direction, data, commandCorrelations) {
  const bytes = Buffer.from(data);
  const parsed = parsedMessage(bytes);
  const value = parsed?.value;
  const payload = parsed?.payload;
  const frame = payload?.frame;
  const command = commandCorrelation(value, bytes);
  if (command) commandCorrelations.set(command.operationId, command);
  const response =
    typeof payload?.operationId === 'string'
      ? responseCorrelation(payload, commandCorrelations.get(payload.operationId))
      : responseCorrelation(null, null);
  return {
    direction,
    bytes: bytes.length,
    wireSha256: sha256(bytes),
    messageType: typeof value?.type === 'string' ? value.type : null,
    issuerKeyId: typeof value?.issuerKeyId === 'string' ? value.issuerKeyId : null,
    sequence: Number.isSafeInteger(value?.sequence) ? value.sequence : null,
    evidenceSha256: typeof value?.sha256 === 'string' ? value.sha256 : null,
    target: typeof value?.target === 'string' ? value.target : null,
    status: typeof value?.status === 'string' ? value.status : null,
    operationId:
      typeof value?.operationId === 'string'
        ? value.operationId
        : typeof payload?.operationId === 'string'
          ? payload.operationId
          : null,
    expectedIntentSha256: command?.expectedIntentSha256 ?? response.expectedIntentSha256,
    expectedRequestSha256: command?.requestSha256 ?? response.expectedRequestSha256,
    responseIntentSha256: response.responseIntentSha256,
    responseRequestSha256: response.responseRequestSha256,
    correlationMatches: response.correlationMatches,
    outcome: typeof payload?.outcome === 'string' ? payload.outcome : null,
    resultingRevision: Number.isSafeInteger(payload?.resultingRevision)
      ? payload.resultingRevision
      : null,
    frameMode: typeof frame?.mode === 'string' ? frame.mode : null,
    frameRevision: Number.isSafeInteger(frame?.revision) ? frame.revision : null,
    confirmedAt: Number.isSafeInteger(frame?.confirmedAt) ? frame.confirmedAt : null,
    observations: Array.isArray(frame?.observations)
      ? frame.observations.map((observation) => ({
          controlId: observation?.subject?.controlId ?? null,
          target: observation?.subject?.target ?? null,
          value: observation?.value ?? null,
          revision: observation?.revision ?? null,
          observedAt: observation?.observedAt ?? null,
        }))
      : [],
  };
}

function isStateFrame(data) {
  const type = parsedMessage(data)?.value?.type;
  return type === 'device.bootstrap.snapshot' || type === 'device.state.delta';
}

const server = http.createServer((request, response) => {
  response.writeHead(426, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ error: 'websocket_upgrade_required' }));
});
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  if (request.url !== '/device') {
    socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  const protocol = request.headers['sec-websocket-protocol'];
  if (protocol !== 'overlaykit.device.v1') {
    socket.write(
      'HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Protocol: overlaykit.device.v1\r\nConnection: close\r\n\r\n'
    );
    socket.destroy();
    return;
  }
  wss.handleUpgrade(request, socket, head, (client) => {
    wss.emit('connection', client, request);
  });
});

wss.on('connection', (client, request) => {
  if (mode === 'offline') {
    record('fault.offline_connection_rejected');
    client.close(1013, 'h034_offline');
    return;
  }
  const upstream = new WebSocket(UPSTREAM, 'overlaykit.device.v1', {
    headers: { Authorization: request.headers.authorization || '' },
    followRedirects: false,
    perMessageDeflate: false,
  });
  downstream = client;
  const commandCorrelations = new Map();
  record('transport.opening');

  upstream.on('open', () => {
    record('transport.open');
  });
  upstream.on('unexpected-response', (_request, response) => {
    record('transport.upstream_rejected', { statusCode: response.statusCode ?? null });
    client.close(1008, 'upstream_rejected');
  });
  upstream.on('message', (data, isBinary) => {
    const details = messageDetails('server-to-companion', data, commandCorrelations);
    record('frame.observed', details);
    const send = () => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(data, { binary: isBinary });
        record('frame.forwarded', details);
      }
    };
    if (mode === 'delay-state' && isStateFrame(data)) {
      record('fault.state_delayed', { ...details, delayMs });
      setTimeout(send, delayMs);
    } else {
      send();
    }
  });
  client.on('message', (data, isBinary) => {
    const details = messageDetails('companion-to-server', data, commandCorrelations);
    record('frame.observed', details);
    if (upstream.readyState === WebSocket.OPEN) upstream.send(data, { binary: isBinary });
  });
  const closeBoth = (source, code, reason) => {
    record('transport.closed', {
      source,
      code,
      reason: Buffer.from(reason || '')
        .toString('utf8')
        .slice(0, 160),
    });
    if (client.readyState !== WebSocket.CLOSED) client.close(code || 1000);
    if (upstream.readyState !== WebSocket.CLOSED) upstream.close(code || 1000);
    if (downstream === client) downstream = null;
  };
  client.on('close', (code, reason) => closeBoth('companion', code, reason));
  upstream.on('close', (code, reason) => closeBoth('server', code, reason));
  client.on('error', (error) =>
    record('transport.error', { source: 'companion', message: error.message })
  );
  upstream.on('error', (error) =>
    record('transport.error', { source: 'server', message: error.message })
  );
});

server.listen(LISTEN_PORT, '0.0.0.0', () => record('proxy.started', { listenPort: LISTEN_PORT }));

const control = http.createServer((request, response) => {
  const chunks = [];
  request.on('data', (chunk) => chunks.push(chunk));
  request.on('end', () => {
    try {
      const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
      if (request.method !== 'POST' || request.url !== '/fault') {
        response.writeHead(404).end();
        return;
      }
      if (body.mode === 'protocol-failure') {
        record('fault.protocol_failure_injected');
        if (downstream?.readyState === WebSocket.OPEN) downstream.send('{');
      } else if (body.mode === 'disconnect') {
        record('fault.disconnect_injected');
        downstream?.close(1011, 'h034_disconnect');
      } else if (VALID_MODES.has(body.mode)) {
        mode = body.mode;
        if (Number.isSafeInteger(body.delayMs) && body.delayMs >= 3001 && body.delayMs <= 10000) {
          delayMs = body.delayMs;
        }
        record('fault.mode_changed', { selectedMode: mode, delayMs });
      } else {
        throw new Error('unsupported fault mode');
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ mode, delayMs }));
    } catch (error) {
      response.writeHead(400, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: error.message }));
    }
  });
});
control.listen(CONTROL_PORT, '0.0.0.0', () =>
  record('proxy.control_started', { controlPort: CONTROL_PORT })
);
