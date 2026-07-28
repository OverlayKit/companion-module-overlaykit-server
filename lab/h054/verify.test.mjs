import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';
import { createHash } from 'node:crypto';
import { buildH054Evidence } from './inventory-lib.mjs';
import { InvalidH054VerificationError, verifyH054File, verifyH054Run } from './verify.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h054');
const RUNS_ROOT = path.join(ARTIFACT_ROOT, 'runs');

const RAW_SAFETY_IDS = Object.freeze({
  weakMode: 'f'.repeat(64),
  noncanonical: 'e'.repeat(64),
  symlink: 'd'.repeat(64),
});

const RAW_SAFETY_PATHS = Object.freeze({
  weakMode: path.join(RUNS_ROOT, RAW_SAFETY_IDS.weakMode),
  noncanonical: path.join(RUNS_ROOT, RAW_SAFETY_IDS.noncanonical),
  symlink: path.join(RUNS_ROOT, RAW_SAFETY_IDS.symlink),
  symlinkTarget: path.join(ARTIFACT_ROOT, `verify-test-target-${process.pid}`),
});

let canonicalRun;
let canonicalReceipt;

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalValue(entry));
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function clone(value) {
  return structuredClone(value);
}

function refreshLayer(layer) {
  layer.entryCount = layer.entries.length;
  layer.contentSha256 = canonicalHash({
    schemaVersion: layer.schemaVersion,
    id: layer.id,
    kind: layer.kind,
    metadata: layer.metadata,
    entries: layer.entries,
  });
}

function layerReceipts(layers) {
  return layers
    .map(({ id, kind, entryCount, contentSha256 }) => ({
      id,
      kind,
      entryCount,
      contentSha256,
    }))
    .sort((left, right) => compareUtf8(left.id, right.id));
}

function snapshotRoot(snapshot, receipts) {
  return canonicalHash({
    schemaVersion: 'overlaykit-h054-layer-set/v1',
    anchors: snapshot.anchors,
    runtimeSelection: null,
    layers: receipts,
  });
}

function refreshSnapshots(run) {
  const receipts = layerReceipts(run.inventory.pre.layers);
  run.inventory.pre.layerReceipts = receipts;
  run.inventory.pre.rootSha256 = snapshotRoot(run.inventory.pre, receipts);
  run.inventory.post.anchors = clone(run.inventory.pre.anchors);
  run.inventory.post.runtimeCandidates = clone(run.inventory.pre.runtimeCandidates);
  run.inventory.post.runtimeSelection = run.inventory.pre.runtimeSelection;
  run.inventory.post.layerReceipts = clone(receipts);
  run.inventory.post.rootSha256 = snapshotRoot(run.inventory.post, receipts);
  run.inventory.stability = {
    stable: true,
    preRootSha256: run.inventory.pre.rootSha256,
    postRootSha256: run.inventory.post.rootSha256,
    changedLayers: [],
  };
}

function refreshRunIdentity(run) {
  delete run.runId;
  delete run.semanticSha256;
  const semanticSha256 = canonicalHash(run);
  run.runId = `h054-${semanticSha256.slice(0, 24)}`;
  run.semanticSha256 = semanticSha256;
  return run;
}

function coherentlyRehash(run) {
  refreshSnapshots(run);
  return refreshRunIdentity(run);
}

function reasonCode(expected) {
  return (error) => {
    assert.ok(error instanceof InvalidH054VerificationError);
    assert.equal(error.reasonCode, expected);
    return true;
  };
}

function removeSafetyFixtures() {
  for (const target of Object.values(RAW_SAFETY_PATHS)) {
    rmSync(target, { recursive: true, force: true });
  }
}

before(() => {
  canonicalRun = buildH054Evidence();
  canonicalReceipt = verifyH054Run(canonicalRun);
});

after(() => {
  removeSafetyFixtures();
});

test('the independent verifier imports only node:* modules and no local implementation', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  const importSpecifiers = [...source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/gu)].map(
    (match) => match[1]
  );

  assert.ok(importSpecifiers.length > 0);
  assert.ok(importSpecifiers.every((specifier) => specifier.startsWith('node:')));
  assert.doesNotMatch(source, /\bfrom\s+['"]\.{1,2}\//u);
  assert.doesNotMatch(source, /\bfrom\s+['"][^'"]*inventory-lib\.mjs['"]/u);
  assert.doesNotMatch(source, /\bfrom\s+['"][^'"]*run\.mjs['"]/u);
  assert.doesNotMatch(source, /\bfrom\s+['"][^'"]*tools\/governance/u);
  assert.match(source, /reapplyH054Controls/u);
  assert.match(source, /canonicalHashIndependent/u);
  assert.match(source, /assertNoSymlinkAncestors\(REPOSITORY_ROOT,\s*absolutePath\)/u);
  assert.match(source, /assertDirectorySafety\(h054Root,\s*0o700/u);
  assert.match(source, /assertDirectorySafety\(runsRoot,\s*0o700/u);
});

test('the producer output passes complete independent reconstruction', () => {
  assert.equal(canonicalReceipt.schemaVersion, 'overlaykit-h054-independent-verification/v1');
  assert.equal(canonicalReceipt.hypothesis, 'H-054');
  assert.equal(canonicalReceipt.runId, canonicalRun.runId);
  assert.equal(canonicalReceipt.semanticSha256, canonicalRun.semanticSha256);
  assert.equal(canonicalReceipt.inventoryRootSha256, canonicalRun.inventory.pre.rootSha256);
  assert.equal(canonicalReceipt.authority, 'none');
  assert.equal(canonicalReceipt.action, null);
});

test('the independently reconstructed cardinalities and runtime/control boundaries are exact', () => {
  assert.equal(canonicalReceipt.mainEntryCount, 319);
  assert.equal(canonicalReceipt.guardedRegularFileCount, 40);
  assert.equal(canonicalReceipt.h053ApparatusRegularFileCount, 10);
  assert.equal(canonicalReceipt.packageRegularFileCount, 587);
  assert.equal(canonicalReceipt.runtimeSelection, null);
  assert.equal(canonicalReceipt.controlCount, 12);
  assert.equal(canonicalReceipt.controls.length, 12);
  assert.ok(canonicalReceipt.controls.every(({ passed }) => passed === true));
  assert.equal(canonicalReceipt.outcome.status, 'inconclusive');
  assert.equal(canonicalReceipt.outcome.supportEligible, false);
  assert.equal(canonicalReceipt.outcome.h055Ready, false);
  assert.ok(canonicalReceipt.openIssues.includes('runtime-selection-unresolved'));
});

test('a coherently rehashed errors.ts omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const errorsLayer = tampered.inventory.pre.layers.find(({ id }) => id === 'source/errors-ts');
  assert.ok(errorsLayer);
  assert.equal(errorsLayer.entries.length, 1);
  errorsLayer.entries = [];
  refreshLayer(errorsLayer);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('required-entry-omitted'));
});

test('a coherently rehashed Ajv transitive omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const ajvLayer = tampered.inventory.pre.layers.find(({ id }) => id === 'package/ajv@8.20.0');
  assert.ok(ajvLayer);
  const target = 'node_modules/ajv/dist/core.js';
  assert.ok(ajvLayer.entries.some(({ logicalPath }) => logicalPath === target));
  ajvLayer.entries = ajvLayer.entries.filter(({ logicalPath }) => logicalPath !== target);
  refreshLayer(ajvLayer);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('package-tree-entry-omitted'));
});

test('a coherently rehashed loader-configuration omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const configuration = tampered.inventory.pre.layers.find(
    ({ id }) => id === 'configuration/loader-and-package-resolution'
  );
  assert.ok(configuration);
  assert.ok(configuration.entries.some(({ logicalPath }) => logicalPath === 'package-lock.json'));
  configuration.entries = configuration.entries.filter(
    ({ logicalPath }) => logicalPath !== 'package-lock.json'
  );
  refreshLayer(configuration);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('configuration-entry-omitted'));
});

test('a coherently rehashed H-054 directory-descriptor omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const apparatus = tampered.inventory.pre.layers.find(
    ({ id }) => id === 'apparatus/h054-producer'
  );
  assert.ok(apparatus);
  assert.ok(apparatus.entries.some(({ logicalPath }) => logicalPath === 'lab/h054'));
  apparatus.entries = apparatus.entries.filter(({ logicalPath }) => logicalPath !== 'lab/h054');
  refreshLayer(apparatus);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('h054-apparatus-entry-omitted'));
});

test('a coherently rehashed supported promotion is rejected while the boundary is open', () => {
  const tampered = clone(canonicalRun);
  tampered.experiment.outcome.status = 'supported';
  refreshRunIdentity(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('supported-with-open-boundary'));
});

test('a coherently rehashed runtime selection is rejected', () => {
  const tampered = clone(canonicalRun);
  tampered.runtimeSelection = 'node22';
  tampered.inventory.pre.runtimeSelection = 'node22';
  tampered.inventory.post.runtimeSelection = 'node22';
  tampered.inventory.pre.runtimeCandidates[0].selection = 'selected';
  tampered.inventory.post.runtimeCandidates[0].selection = 'selected';
  tampered.interpretation.runtimeDecision.selected = 'node22';
  refreshRunIdentity(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('runtime-selection-not-null'));
});

test('a coherently rehashed control receipt tamper is rejected', () => {
  const tampered = clone(canonicalRun);
  tampered.controls[0].passed = false;
  tampered.controls[0].observedReasonCode = 'hostile-self-certified-reason';
  refreshRunIdentity(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('control-roster-or-receipt-drift'));
});

test('a coherently rehashed stale main anchor is rejected', () => {
  const tampered = clone(canonicalRun);
  const staleTree = '0'.repeat(40);
  tampered.anchors.mainTree = staleTree;
  tampered.inventory.pre.anchors.mainTree = staleTree;
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('anchor-drift'));
});

test('a coherently rehashed top-level anchor divergence is rejected', () => {
  const tampered = clone(canonicalRun);
  tampered.anchors = { ...tampered.anchors, mainTree: '0'.repeat(40) };
  refreshRunIdentity(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('run-anchor-drift'));
});

test('a coherently rehashed historical-closure overclaim is rejected', () => {
  const tampered = clone(canonicalRun);
  tampered.inventory.historicalReconstruction.h053Closed = true;
  tampered.inventory.historicalReconstruction.classification = 'closed';
  tampered.inventory.historicalReconstruction.missing = [];
  refreshRunIdentity(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('inventory-classification-drift'));
});

test('a coherently rehashed capability-closure overclaim is rejected', () => {
  const tampered = clone(canonicalRun);
  tampered.capabilityAudit.closed = true;
  tampered.capabilityAudit.unknowns = [];
  refreshRunIdentity(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('unauthorized-capability-recorded'));
});

test('a coherently rehashed forged producer argv is rejected', () => {
  const tampered = clone(canonicalRun);
  const invocationLayer = tampered.inventory.pre.layers.find(
    ({ id }) => id === 'process/invocation'
  );
  assert.ok(invocationLayer);
  invocationLayer.metadata.argv = ['FORGED-ARGV'];
  refreshLayer(invocationLayer);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('process-invocation-drift'));
});

test('the in-memory verifier rejects a forged canonical-writer invocation', () => {
  const tampered = clone(canonicalRun);
  const invocationLayer = tampered.inventory.pre.layers.find(
    ({ id }) => id === 'process/invocation'
  );
  assert.ok(invocationLayer);
  invocationLayer.metadata.argv = [
    invocationLayer.metadata.executablePath,
    path.join(REPOSITORY_ROOT, 'lab', 'h054', 'run.mjs'),
    '--write',
  ];
  invocationLayer.metadata.execArgv = [];
  refreshLayer(invocationLayer);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('process-invocation-drift'));
});

test('a coherently rehashed complete libnode omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const node22Layer = tampered.inventory.pre.layers.find(
    ({ id }) => id === 'runtime/node22-candidate'
  );
  assert.ok(node22Layer);
  const libnodeEntries = node22Layer.entries.filter(({ logicalPath }) =>
    logicalPath.endsWith('/libnode.so.127')
  );
  assert.ok(libnodeEntries.length > 0);
  node22Layer.entries = node22Layer.entries.filter(
    ({ logicalPath }) => !logicalPath.endsWith('/libnode.so.127')
  );
  refreshLayer(node22Layer);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('runtime-library-omitted'));
});

test('a coherently rehashed Git-library omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const gitLayer = tampered.inventory.pre.layers.find(({ id }) => id === 'tool/git-runtime');
  assert.ok(gitLayer);
  const omitted = gitLayer.entries.filter(
    ({ logicalPath }) => logicalPath.includes('/libpcre2-8.so') || logicalPath.includes('/libz.so')
  );
  assert.ok(omitted.length > 0);
  const omittedPaths = new Set(omitted.map(({ logicalPath }) => logicalPath));
  gitLayer.entries = gitLayer.entries.filter(({ logicalPath }) => !omittedPaths.has(logicalPath));
  refreshLayer(gitLayer);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('git-runtime-library-omitted'));
});

test('a coherently rehashed environment-selector omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const environment = tampered.inventory.pre.layers.find(({ id }) => id === 'process/environment');
  assert.ok(environment);
  const before = environment.metadata.semanticVariables.length;
  environment.metadata.semanticVariables = environment.metadata.semanticVariables.filter(
    ({ name }) => name !== 'TSX_DISABLE_CACHE'
  );
  assert.equal(environment.metadata.semanticVariables.length, before - 1);
  refreshLayer(environment);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('environment-selector-omitted'));
});

test('a coherently rehashed Git HEAD omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const gitState = tampered.inventory.pre.layers.find(
    ({ id }) => id === 'tool/git-repository-state'
  );
  assert.ok(gitState);
  assert.ok(gitState.entries.some(({ logicalPath }) => logicalPath === '.git/HEAD'));
  gitState.entries = gitState.entries.filter(({ logicalPath }) => logicalPath !== '.git/HEAD');
  refreshLayer(gitState);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('git-repository-state-entry-omitted'));
});

test('a coherently rehashed host-context omission is rejected', () => {
  const tampered = clone(canonicalRun);
  const host = tampered.inventory.pre.layers.find(({ id }) => id === 'host/context');
  assert.ok(host);
  const target = host.entries.find(({ logicalPath }) => logicalPath.endsWith('/etc/ld.so.cache'));
  assert.ok(target);
  host.entries = host.entries.filter(({ logicalPath }) => logicalPath !== target.logicalPath);
  refreshLayer(host);
  coherentlyRehash(tampered);

  assert.throws(() => verifyH054Run(tampered), reasonCode('host-context-entry-omitted'));
});

test('file verification rejects a path outside the ignored H-054 run root', () => {
  assert.throws(
    () => verifyH054File(path.join(LAB_DIRECTORY, 'subject-lock.json')),
    reasonCode('run-path-invalid')
  );
});

test('file verification rejects weak raw-file permissions before parsing', () => {
  removeSafetyFixtures();
  mkdirSync(RAW_SAFETY_PATHS.weakMode, { recursive: true, mode: 0o700 });
  const runPath = path.join(RAW_SAFETY_PATHS.weakMode, 'run.json');
  writeFileSync(runPath, '{}\n', { mode: 0o644 });
  chmodSync(runPath, 0o644);

  assert.throws(() => verifyH054File(runPath), reasonCode('run-file-unsafe'));
});

test('file verification rejects noncanonical raw serialization', () => {
  rmSync(RAW_SAFETY_PATHS.noncanonical, { recursive: true, force: true });
  mkdirSync(RAW_SAFETY_PATHS.noncanonical, { recursive: true, mode: 0o700 });
  const runPath = path.join(RAW_SAFETY_PATHS.noncanonical, 'run.json');
  writeFileSync(runPath, '{"schemaVersion":"synthetic-not-a-run"}\n', { mode: 0o600 });
  chmodSync(runPath, 0o600);

  assert.throws(() => verifyH054File(runPath), reasonCode('run-serialization-noncanonical'));
});

test('file verification rejects a symlinked run-directory ancestor', () => {
  rmSync(RAW_SAFETY_PATHS.symlink, { recursive: true, force: true });
  rmSync(RAW_SAFETY_PATHS.symlinkTarget, { recursive: true, force: true });
  mkdirSync(RUNS_ROOT, { recursive: true, mode: 0o700 });
  mkdirSync(RAW_SAFETY_PATHS.symlinkTarget, { mode: 0o700 });
  symlinkSync(RAW_SAFETY_PATHS.symlinkTarget, RAW_SAFETY_PATHS.symlink, 'dir');

  assert.throws(
    () => verifyH054File(path.join(RAW_SAFETY_PATHS.symlink, 'run.json')),
    reasonCode('run-path-symlink')
  );
});
