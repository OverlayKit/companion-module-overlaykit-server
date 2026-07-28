import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  H054_CONSTANTS,
  InvalidH054InventoryError,
  buildH054Evidence,
  canonicalJsonBytewise,
  canonicalPrettyJsonBytewise,
  compareUtf8Bytewise,
  validateH054RunIdentity,
} from './inventory-lib.mjs';

const EXPECTED_ANCHORS = Object.freeze({
  mainCommit: '161554b968b6dc38fb1cc055c829b414ba5b85ae',
  mainTree: 'd8087b92796a8be07ee5779a5847e0e3859930a0',
  h053ClosureSha256: 'e84b9faeb4858549eec513c3a08f19da566987665f4c79a448102dbc957b4911',
  h053RunRawSha256: '5a55fc6ec2dff653858d4c8a70a22d3085400b423b8c93e265f14774078bf14f',
});

const EXPECTED_RECEIPTS = Object.freeze({
  mainRecursiveEntryCount: 319,
  mainRecursiveLsTreeSha256: '9c5dc303da5ed8da64ee59c78e5cd5a3efaab617e93ab502925a884364d9cde1',
  guardedRegularFileCount: 40,
  h053GuardedSurfaceSha256: '4f3d19de30dc7df9819037004a27672a7b319693cc6fff54ad081a2999056ce8',
  h053ApparatusRegularFileCount: 10,
  h053ApparatusSha256: '1c686c08b995890b39ab750e0fc593766d5916fed2dfc5e6f657ea51f6b40126',
  packageRegularFileCount: 587,
});

const EXPECTED_LAYER_IDS = Object.freeze([
  'apparatus/h053',
  'apparatus/h054-producer',
  'cache/tsx-global-current',
  'configuration/loader-and-package-resolution',
  'evidence/h053-canonical-run',
  'evidence/h053-post-review-closure',
  'host/context',
  'native/esbuild-linux-x64@0.28.1',
  'package/@esbuild/linux-x64@0.28.1',
  'package/ajv@8.20.0',
  'package/esbuild@0.28.1',
  'package/fast-deep-equal@3.1.3',
  'package/fast-uri@3.1.4',
  'package/json-schema-traverse@1.0.0',
  'package/require-from-string@2.0.2',
  'package/tsx@4.23.1',
  'process/environment',
  'process/invocation',
  'runtime/node22-candidate',
  'runtime/node24-candidate',
  'source/errors-ts',
  'source/guarded-worktree',
  'source/main-git-tree',
  'tool/git-repository-state',
  'tool/git-runtime',
]);

const EXPECTED_CONTROL_IDS = Object.freeze([
  'omit-errors-ts',
  'omit-ajv-transitive',
  'omit-esbuild-native',
  'omit-node-final-or-libnode',
  'omit-git-or-library',
  'omit-env-cache-selector',
  'stale-main-anchor',
  'stale-h053-closure',
  'stale-apparatus',
  'symlink-retarget',
  'symlink-cycle-escape',
  'flatten-layer-collision',
]);

let cachedRun;

function h054Run() {
  cachedRun ??= buildH054Evidence();
  return cachedRun;
}

function reasonCodeIs(reasonCode) {
  return (error) => {
    assert.ok(error instanceof InvalidH054InventoryError);
    assert.equal(error.reasonCode, reasonCode);
    return true;
  };
}

test('canonical JSON orders object keys bytewise by UTF-8 and preserves arrays', () => {
  assert.ok(compareUtf8Bytewise('\uE000', '\u{10000}') < 0);
  const value = {
    '\u{10000}': { z: 1, a: 2 },
    '\uE000': true,
    a: ['z', 'a'],
  };
  const compact = '{"a":["z","a"],"":true,"𐀀":{"a":2,"z":1}}';

  assert.equal(canonicalJsonBytewise(value), compact);
  assert.equal(canonicalPrettyJsonBytewise(value).at(-1), '\n');
  assert.deepEqual(JSON.parse(canonicalPrettyJsonBytewise(value)), JSON.parse(compact));
});

test('the inventory has the exact anchors, receipts, layers, and null candidates', () => {
  const run = h054Run();
  assert.equal(validateH054RunIdentity(run), run.semanticSha256);
  assert.deepEqual(run.anchors, EXPECTED_ANCHORS);
  assert.deepEqual(run.inventory.pre.anchors, EXPECTED_ANCHORS);
  assert.deepEqual(run.inventory.pre.exactReceipts, EXPECTED_RECEIPTS);
  assert.deepEqual(
    run.inventory.pre.layers.map(({ id }) => id),
    EXPECTED_LAYER_IDS
  );
  assert.equal(run.inventory.pre.layers.length, 25);
  assert.deepEqual(run.inventory.pre.runtimeCandidates, [
    {
      id: 'node22',
      version: 'v22.22.2',
      executablePath: '/usr/bin/node-22',
      selection: null,
    },
    {
      id: 'node24',
      version: 'v24.16.0',
      executablePath: '/home/rod/.local/share/nodejs/node-v24.16.0-linux-x64/bin/node',
      selection: null,
    },
  ]);
  assert.equal(run.runtimeSelection, null);
  assert.equal(run.inventory.pre.runtimeSelection, null);
  assert.equal(run.inventory.post.runtimeSelection, null);
  assert.equal(run.interpretation.runtimeDecision.selected, null);
  for (const layer of run.inventory.pre.layers) {
    assert.equal(layer.entryCount, layer.entries.length, layer.id);
    assert.match(layer.contentSha256, /^[0-9a-f]{64}$/u, layer.id);
  }
  const packageLayers = run.inventory.pre.layers.filter(({ id }) => id.startsWith('package/'));
  assert.deepEqual(
    packageLayers.filter(({ metadata }) => metadata.seed).map(({ metadata }) => metadata.name),
    ['ajv', 'tsx']
  );
  assert.deepEqual(
    packageLayers.find(({ metadata }) => metadata.name === 'ajv').metadata.requiredDependencies,
    ['fast-deep-equal', 'fast-uri', 'json-schema-traverse', 'require-from-string']
  );
  assert.deepEqual(
    packageLayers.find(({ metadata }) => metadata.name === 'esbuild').metadata
      .followedOptionalDependencies,
    ['@esbuild/linux-x64']
  );
  assert.ok(
    packageLayers.every(
      ({ metadata }) =>
        typeof metadata.lockIntegrity === 'string' &&
        typeof metadata.lockResolved === 'string' &&
        metadata.derivation.includes('human-nominated H-053 seeds')
    )
  );
});

test('the exact twelve controls pass and the strict open boundary remains inconclusive', () => {
  const run = h054Run();
  assert.deepEqual(H054_CONSTANTS.controlIds, EXPECTED_CONTROL_IDS);
  assert.deepEqual(
    run.controls.map(({ id }) => id),
    EXPECTED_CONTROL_IDS
  );
  assert.equal(run.controls.length, 12);
  assert.ok(
    run.controls.every(
      ({ passed, expectedReasonCode, observedReasonCode }) =>
        passed === true && observedReasonCode === expectedReasonCode
    )
  );

  assert.deepEqual(run.experiment.outcome.failedControlIds, []);
  assert.equal(run.experiment.outcome.status, 'inconclusive');
  assert.equal(
    run.experiment.outcome.reasonCode,
    'runtime-selection-null-or-boundary-input-unclosed'
  );
  assert.equal(run.inventory.successorEligibility.h055Ready, false);
  assert.deepEqual(
    run.experiment.outcome.blockingClassifications.map(({ id }) => id).sort(compareUtf8Bytewise),
    [
      'dynamic-library-inspector-closure',
      'historical-h053-cache-attribution',
      'opaque-host-execution-context',
      'package-entry-point-resolution-method',
      'runtime-selection-null',
      'unclassified-environment-values',
    ]
  );
  assert.equal(run.authority, 'none');
  assert.equal(run.action, null);
});

test('producer and writer have no static or dynamic verify.mjs import', () => {
  for (const relativePath of ['./inventory-lib.mjs', './run.mjs']) {
    const source = readFileSync(new URL(relativePath, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /(?:from\s*|import\s*\()\s*['"]\.\/verify\.mjs['"]/u, relativePath);
  }
});

test('identity, runtime-selection, and supported-status tampering fail closed', () => {
  const identityTamper = structuredClone(h054Run());
  identityTamper.experiment.outcome.claimBoundary = 'tampered-boundary';
  assert.throws(
    () => validateH054RunIdentity(identityTamper),
    reasonCodeIs('run-identity-invalid')
  );

  const runtimeTamper = structuredClone(h054Run());
  runtimeTamper.runtimeSelection = 'node22';
  assert.throws(
    () => validateH054RunIdentity(runtimeTamper),
    reasonCodeIs('runtime-selection-not-null')
  );

  const polarityTamper = structuredClone(h054Run());
  polarityTamper.experiment.outcome.status = 'supported';
  assert.throws(
    () => validateH054RunIdentity(polarityTamper),
    reasonCodeIs('outcome-policy-drift')
  );
});
