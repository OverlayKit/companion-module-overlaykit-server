import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { H043_REPLAY_ARCHIVE_PATH, readHistoricalEvidence } from './admission-lib.mjs';
import { classifyLiveFrames } from './classifier-lib.mjs';
import {
  H044_CLAIM_BOUNDARY,
  H044_REQUIRED_CASE_IDS,
  buildCapabilityAudit,
  evaluateHostileMatrix,
  normalizeObservationFrame,
  outcomeFor,
  runH044,
} from './run.mjs';
import { verifyRun } from './verify.mjs';

async function candidate() {
  return readHistoricalEvidence(await readFile(H043_REPLAY_ARCHIVE_PATH)).candidate;
}

test('hostile matrix covers the exact required refutation set without an unsafe positive', async () => {
  const matrix = evaluateHostileMatrix(await candidate());
  assert.deepEqual(matrix.requiredCaseIds, H044_REQUIRED_CASE_IDS);
  assert.deepEqual(
    matrix.cases.map((entry) => entry.id),
    H044_REQUIRED_CASE_IDS
  );
  assert.equal(matrix.caseCount, 16);
  assert.equal(matrix.passedCount, 16);
  assert.equal(matrix.allPassed, true);
  assert.equal(
    matrix.cases.every((entry) => entry.actualReceiptCount === 0),
    true
  );
});

test('normalizes a complete historical-container absence into a schema-shaped withheld frame', async () => {
  const historical = await candidate();
  const raw = {
    frameId: 'frame-1',
    complete: true,
    startedAt: '2026-07-26T20:00:00.000Z',
    endedAt: '2026-07-26T20:00:00.100Z',
    startedMonotonicNs: '1000000000',
    endedMonotonicNs: '1100000000',
    observationCutoff: {
      at: '2026-07-26T20:00:00.080Z',
      monotonicNs: '1080000000',
    },
    errors: [],
    host: {
      hostname: 'linux',
      bootId: '00000000-0000-4000-8000-000000000044',
      osRelease: { id: 'linux', versionId: '1', prettyName: 'Linux' },
    },
    device: {
      complete: true,
      present: true,
      usbEpochs: [
        {
          ...historical.identity.device.revalidationEpoch,
          vendorId: '0fd9',
          productId: '0080',
        },
      ],
    },
    docker: {
      ps: [],
      lifecycle: null,
      markers: { entries: [], openingCount: 0, readyCount: 0 },
    },
    processes: {
      pid1: null,
      surfaceWorkers: [],
    },
  };
  const first = normalizeObservationFrame(raw, historical);
  const second = normalizeObservationFrame(
    {
      ...structuredClone(raw),
      frameId: 'frame-2',
      startedAt: raw.endedAt,
      endedAt: '2026-07-26T20:00:00.200Z',
      startedMonotonicNs: raw.endedMonotonicNs,
      endedMonotonicNs: '1200000000',
      observationCutoff: {
        at: '2026-07-26T20:00:00.180Z',
        monotonicNs: '1180000000',
      },
    },
    historical
  );
  const commandSnapshot = {
    receipts: [
      {
        index: 0,
        kind: 'gitRevParse',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '1',
        endedMonotonicNs: '2',
      },
      {
        index: 1,
        kind: 'gitMergeBaseAncestor',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '2',
        endedMonotonicNs: '3',
      },
      {
        index: 2,
        kind: 'gitRemoteGetUrl',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '3',
        endedMonotonicNs: '4',
      },
      {
        index: 3,
        kind: 'lsusb',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '4',
        endedMonotonicNs: '5',
      },
      {
        index: 4,
        kind: 'dockerVersion',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '5',
        endedMonotonicNs: '6',
      },
      {
        index: 5,
        kind: 'dockerPs',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '6',
        endedMonotonicNs: '7',
      },
      {
        index: 6,
        kind: 'dockerPs',
        exitCode: 0,
        signal: null,
        errorCode: null,
        startedMonotonicNs: '7',
        endedMonotonicNs: '8',
      },
    ],
    rejectedAttempts: [],
    prohibited: {},
  };
  const filesystemSnapshot = {
    receipts: [
      {
        index: 0,
        operation: 'readFileSync',
        path: '/proc/sys/kernel/random/boot_id',
        disposition: 'observed',
        errorCode: null,
        startedMonotonicNs: '6',
        endedMonotonicNs: '7',
      },
    ],
    rejectedAttempts: [],
  };
  const audit = buildCapabilityAudit(commandSnapshot, filesystemSnapshot, [first, second]);
  const classification = classifyLiveFrames({
    historicalCandidate: historical,
    frames: [first, second],
    capabilityAudit: audit,
    sourceAdmissionExact: true,
  });
  assert.equal(first.complete, true);
  assert.deepEqual(first.containerObservation, {
    present: false,
    state: null,
    exact: true,
  });
  assert.deepEqual(first.absence, { historicalContainerAbsent: true, exact: true });
  assert.equal(classification.disposition, 'withheld');
  assert.equal(classification.reasonCode, 'historical-container-absent');
  assert.deepEqual(classification.receipts, []);
});

test('outcome separates hypothesis support from live candidate disposition', async () => {
  const matrix = evaluateHostileMatrix(await candidate());
  const source = { allExact: true };
  const audit = {
    complete: true,
    exact: true,
    prohibitedCounts: {
      externalNetwork: 0,
      hidrawOpen: 0,
      hidrawRead: 0,
      hidrawWrite: 0,
      hidrawIoctl: 0,
      signal: 0,
      lifecycleMutation: 0,
      configurationMutation: 0,
      mountMutation: 0,
      cgroupMutation: 0,
      sysfsWrite: 0,
      productionMutation: 0,
    },
  };
  assert.deepEqual(
    outcomeFor(
      source,
      audit,
      {
        disposition: 'withheld',
        stage: 'not-eligible',
        reasonCode: 'historical-container-absent',
        predicates: {
          sourceAdmissionExact: true,
          auditExact: true,
          framesComplete: true,
          frameOrderExact: true,
          exposureBounded: true,
          hostStable: true,
          deviceExact: false,
          lifecycleExact: false,
          pid1Exact: false,
          workerUnique: false,
          workerExact: false,
          descriptorAbsent: true,
          markersStable: true,
        },
        receipts: [],
      },
      matrix
    ),
    {
      status: 'supported',
      stage: 'live-readonly-revalidation',
      reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
    }
  );
  audit.prohibitedCounts.signal = 1;
  assert.equal(outcomeFor(source, audit, {}, matrix).status, 'refuted');
});

test('claim boundary keeps every candidate stale and authority-void', () => {
  assert.equal(H044_CLAIM_BOUNDARY.proves.length, 5);
  assert.equal(H044_CLAIM_BOUNDARY.excludes.length, 8);
  assert.equal(
    H044_CLAIM_BOUNDARY.excludes.some((entry) => entry.includes('race freedom')),
    true
  );
  assert.equal(
    H044_CLAIM_BOUNDARY.excludes.some((entry) => entry.includes('SIGTERM')),
    true
  );
});

test('offline dependency-injected dry run writes schema-valid withheld evidence without live commands', async (t) => {
  const outputRoot = await mkdtemp(path.join(os.tmpdir(), 'overlaykit-h044-dry-'));
  t.after(async () => rm(outputRoot, { recursive: true }));
  let wallMilliseconds = Date.parse('2026-07-26T20:00:00.000Z');
  let monotonic = 1_000_000_000n;
  const wallNow = () => new Date(wallMilliseconds++).toISOString();
  const monotonicNowNs = () => {
    monotonic += 1_000_000n;
    return monotonic;
  };
  const calls = [];
  const runner = async (executable, args) => {
    calls.push({ executable, args: [...args] });
    let stdout = '';
    if (executable === 'git' && args.join(' ') === 'rev-parse HEAD') {
      stdout = '9e2156e7ddc38ebe223824a07f682421b7ee0589\n';
    } else if (
      executable === 'git' &&
      args.join(' ') === 'merge-base --is-ancestor 6c329234caddf9e34126be04149f768673bdb8bf HEAD'
    ) {
      stdout = '';
    } else if (executable === 'git' && args.join(' ') === 'remote get-url origin') {
      stdout = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git\n';
    } else if (executable === 'lsusb' && args.length === 0) {
      stdout = '';
    } else if (executable === 'docker' && args[2] === 'version') {
      stdout = `${JSON.stringify({
        Client: { Version: 'synthetic', ApiVersion: '1.0' },
        Server: { Version: 'synthetic', ApiVersion: '1.0' },
      })}\n`;
    } else if (executable === 'docker' && args[2] === 'ps') {
      stdout = '';
    } else {
      throw new Error(`unexpected fake command ${executable} ${args.join(' ')}`);
    }
    return {
      exitCode: 0,
      signal: null,
      stdout: Buffer.from(stdout),
      stderr: Buffer.alloc(0),
    };
  };
  const missing = () => {
    const error = new Error('missing');
    error.code = 'ENOENT';
    throw error;
  };
  const filesystem = {
    readFileSync(targetPath) {
      if (targetPath === '/etc/os-release') {
        return Buffer.from('ID=linux\nVERSION_ID=1\nPRETTY_NAME="Synthetic Linux"\n');
      }
      if (targetPath === '/proc/sys/kernel/random/boot_id') {
        return Buffer.from('00000000-0000-4000-8000-000000000044\n');
      }
      if (targetPath === '/proc/sys/kernel/hostname') return Buffer.from('synthetic-host\n');
      return missing();
    },
    readdirSync(targetPath) {
      if (targetPath === '/sys/class/hidraw') return [];
      return missing();
    },
    realpathSync: missing,
    statSync: missing,
    lstatSync: missing,
    readlinkSync: missing,
  };
  const { run, runPath } = await runH044({
    outputRoot,
    wallNow,
    monotonicNowNs,
    runner,
    filesystem,
  });
  assert.equal(JSON.parse(await readFile(runPath, 'utf8')).evidenceSha256, run.evidenceSha256);
  assert.equal(run.outcome.status, 'supported');
  assert.equal(run.liveClassification.disposition, 'withheld');
  assert.equal(run.liveClassification.receipts.length, 0);
  assert.equal(run.capabilityAudit.lsusbCount, 1);
  assert.equal(run.capabilityAudit.allowedProcessCounts.dockerPs, 2);
  assert.equal(run.capabilityAudit.allowedProcessCounts.dockerInspect, 0);
  assert.equal(run.capabilityAudit.allowedProcessCounts.dockerLogs, 0);
  const verification = await verifyRun(runPath);
  assert.equal(verification.outcome, 'supported');
  assert.equal(verification.liveDisposition, 'withheld');
  assert.equal(verification.framesExact, true);
  assert.equal(verification.capabilityAuditExact, true);
  assert.equal(verification.producerAgreement, true);
  assert.equal(
    calls
      .filter((call) => call.executable === 'docker')
      .every((call) => call.args[0] === '--host' && call.args[1] === 'unix:///var/run/docker.sock'),
    true
  );
});
