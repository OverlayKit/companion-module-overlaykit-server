import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { before } from 'node:test';

import { buildBoundaryEvidence } from './run.mjs';
import {
  InvalidNode22PreflightEvidenceError,
  canonicalHashIndependent,
  canonicalJsonIndependent,
  reconstructLooseGitAnchor,
  refreshRunIdentityIndependent,
  rerunPositiveBoundary,
  selfCycleLinkTargetIndependent,
  symlinkControlTargetIndependent,
  verifyNode22PreflightFile,
  verifyNode22PreflightRun,
} from './verify.mjs';

const EXPECTED_BLOCKERS = [
  'exhaustive-esm-and-open-file-trace-not-admitted',
  'content-addressed-effective-seccomp-policy-not-admitted',
  'kernel-vdso-and-late-loaded-object-closure-not-established',
  'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
  'worker-and-child-process-cardinality-not-independently-traced',
  'universal-successor-absence-not-provable-without-exhaustive-trace',
  'anchor-resolver-host-dynamic-library-and-git-object-read-closure-not-independently-traced',
  'path-execution-image-identity-not-atomically-bound',
  'successor-apparatus-and-accepted-h054-layer-source-lock-not-established',
  'failed-attempt-evidence-preservation-and-outcome-derivation-not-established',
];

const EXPECTED_CONTROLS = [
  ['stale-temporal-anchor', 'temporal-anchor-stale'],
  ['substitute-node22', 'runtime-identity-drift'],
  ['stale-apparatus', 'apparatus-source-set-drift'],
  ['omit-apparatus-entry', 'apparatus-source-set-drift'],
  ['omit-package-mount', 'module-universe-incomplete'],
  ['omit-import-target', 'module-universe-incomplete'],
  ['stale-ajv-entry', 'module-universe-incomplete'],
  ['enable-tsconfig-fallback', 'loader-config-escape'],
  ['add-tsconfig-extends-chain', 'loader-config-escape'],
  ['inject-environment-selector', 'environment-closure-drift'],
  ['weaken-node-permission-flags', 'permission-envelope-drift'],
  ['broaden-root-bind', 'mount-boundary-broadened'],
  ['add-write-bind', 'mount-boundary-broadened'],
  ['share-network-namespace', 'isolation-policy-drift'],
  ['omit-shared-object', 'native-closure-drift'],
  ['substitute-esbuild-native', 'native-closure-drift'],
  ['symlink-retarget', 'path-resolution-invalid'],
  ['symlink-escape', 'path-resolution-invalid'],
  ['symlink-cycle', 'path-resolution-invalid'],
  ['symlink-dangling', 'path-resolution-invalid'],
  ['scratch-residue', 'mutable-state-observed'],
  ['enable-loader-cache', 'mutable-state-observed'],
  ['working-directory-drift', 'ambient-capability-observed'],
  ['layer-logical-path-collision', 'layer-collision'],
  ['cross-layer-mount-target-collision', 'layer-collision'],
  ['duplicate-attempt-divergence', 'determinism-failure'],
  ['forbidden-subject-import', 'forbidden-subject-path'],
  ['claim-supported-with-blocker', 'outcome-policy-violation'],
  ['receipt-tamper', 'evidence-integrity-drift'],
  ['authority-tamper', 'authority-overclaim'],
  ['false-successor-state', 'successor-state-overclaim'],
];

let run;
let verification;

before(async () => {
  run = await buildBoundaryEvidence();
  verification = verifyNode22PreflightRun(run);
});

function assertInvalidReason(mutated, reasonCode) {
  refreshRunIdentityIndependent(mutated);
  assert.throws(
    () => verifyNode22PreflightRun(mutated),
    (error) =>
      error instanceof InvalidNode22PreflightEvidenceError && error.reasonCode === reasonCode
  );
}

test('the independent verifier imports only Node built-ins', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  const specifiers = [...source.matchAll(/\bfrom\s+['"](?<specifier>[^'"]+)['"]/gu)].map(
    ({ groups }) => groups.specifier
  );

  assert.ok(specifiers.length > 0);
  assert.equal(
    specifiers.every((specifier) => specifier.startsWith('node:')),
    true
  );
  assert.equal(/\bimport\s*\(/u.test(source), false);
  assert.equal(/\bh-?05[35]\b/iu.test(source), false);
});

test('canonical JSON and semantic hashing are independently deterministic', () => {
  const value = { '\u00e9': 4, a: 1, aa: [3, { z: 2, b: true }] };
  const canonical = '{"a":1,"aa":[3,{"b":true,"z":2}],"\u00e9":4}';
  assert.equal(canonicalJsonIndependent(value), canonical);
  assert.equal(
    canonicalHashIndependent(value),
    createHash('sha256').update(canonical, 'utf8').digest('hex')
  );
  assert.throws(
    () => canonicalJsonIndependent({ invalid: undefined }),
    (error) =>
      error instanceof InvalidNode22PreflightEvidenceError &&
      error.reasonCode === 'canonical-value-invalid'
  );
});

test('the symlink-cycle control constructs an actual self-cycle target', () => {
  const requestedPath = '/lib64';
  const linkTarget = selfCycleLinkTargetIndependent(requestedPath);
  assert.equal(linkTarget, 'lib64');
  assert.equal(path.posix.resolve(path.posix.dirname(requestedPath), linkTarget), requestedPath);
});

test('symlink controls use distinct valid, escaping, cyclic, and dangling targets', () => {
  assert.deepEqual(symlinkControlTargetIndependent('symlink-retarget', '/lib64'), {
    linkTarget: 'usr/lib',
    requestedPath: '/lib64',
    resolvedPath: '/usr/lib',
  });
  assert.deepEqual(symlinkControlTargetIndependent('symlink-escape', '/lib64'), {
    linkTarget: 'etc',
    requestedPath: '/lib64',
    resolvedPath: '/etc',
  });
  assert.deepEqual(symlinkControlTargetIndependent('symlink-cycle', '/lib64'), {
    linkTarget: 'lib64',
    requestedPath: '/lib64',
    resolvedPath: '/lib64',
  });
  assert.deepEqual(symlinkControlTargetIndependent('symlink-dangling', '/lib64'), {
    linkTarget: 'node22-preflight-definitely-absent',
    requestedPath: '/lib64',
    resolvedPath: '/node22-preflight-definitely-absent',
  });
});

test('loose Git reconstruction reaches the predecessor manifest blob', () => {
  const anchor = reconstructLooseGitAnchor();
  assert.equal(anchor.commit, 'bb6ce5db53541a7926eb74b3c722fa039ca9dabd');
  assert.equal(anchor.tree, '823796b0c9f509cf4ed35b9febeb71c284626036');
  assert.equal(anchor.predecessorManifest.blobOid, '0ef0c148901fd057b1f042d1d0c2bb4db37c1f09');
  assert.equal(
    anchor.predecessorManifest.rawSha256,
    '8b3fb70d5dc2f8835a2b65b7b882880eb40cdbd58864135ecdaf5b3b105d062e'
  );
  assert.equal(anchor.predecessorManifest.traversedTrees.length, 3);
});

test('the full independent receipt remains narrow, inconclusive, and authority-free', () => {
  assert.equal(
    verification.schemaVersion,
    'overlaykit-node22-boundary-preflight-independent-verification/v1'
  );
  assert.equal(verification.semanticSha256, run.semanticSha256);
  assert.equal(verification.runId, run.runId);
  assert.deepEqual(verification.blockers, EXPECTED_BLOCKERS);
  assert.deepEqual(verification.normalizations, []);
  assert.equal(verification.adrCandidate, null);
  assert.equal(verification.authority, 'none');
  assert.equal(verification.action, null);
  assert.deepEqual(verification.humanReview, { accepted: null, required: true });
  assert.equal(verification.failureBranch, 'not-materializable-by-current-producer');
  assert.equal(
    verification.sourceClosureQualification,
    'current-state-pre-post-observation-not-precontract-anchor'
  );
  assert.deepEqual(verification.outcome, {
    reason: 'known-boundary-completeness-blockers-remain',
    refutationEligible: false,
    status: 'inconclusive',
    supportEligible: false,
  });
  assert.deepEqual(verification.successorState, {
    observation: 'not-observed-within-nominated-boundary',
    syscallTrace: null,
    universalAbsenceProved: false,
  });
});

test('the pinned resolver agrees with the loose audit while retaining its blocker', () => {
  const resolver = verification.protectedAnchors.anchorResolver;
  assert.equal(resolver.executablePath, '/usr/bin/git');
  assert.equal(resolver.version, 'git version 2.55.0');
  assert.equal(
    resolver.executableSha256,
    '8d8d470218586c27909c9b6ae77d18df32a9e05e725044ae2052d60254791c26'
  );
  assert.equal(
    resolver.predecessorManifestRawSha256,
    verification.protectedAnchors.git.predecessorManifest.rawSha256
  );
  assert.ok(
    verification.blockers.includes(
      'anchor-resolver-host-dynamic-library-and-git-object-read-closure-not-independently-traced'
    )
  );
});

test('source closure and duplicate positive attempts reconstruct exactly', () => {
  const closure = run.sourceClosure;
  assert.equal(closure.stable, true);
  assert.equal(closure.preRootSha256, closure.rootSha256);
  assert.equal(closure.postRootSha256, closure.rootSha256);
  assert.equal(verification.sourceRootSha256, closure.rootSha256);
  assert.equal(
    canonicalHashIndependent({ layers: closure.layers, mounts: closure.mounts }),
    closure.rootSha256
  );
  assert.equal(closure.layers.length, closure.mounts.length);
  assert.equal(new Set(closure.layers.map(({ id }) => id)).size, closure.layers.length);
  assert.equal(new Set(closure.mounts.map(({ target }) => target)).size, closure.mounts.length);
  assert.equal(run.attempts.length, 2);
  assert.equal(run.attempts[0].stdoutSha256, run.attempts[1].stdoutSha256);
  assert.equal(
    run.attempts[0].observationSemanticSha256,
    run.attempts[1].observationSemanticSha256
  );
  assert.equal(run.observation.tsconfig.extends, null);
  assert.equal(run.observation.tsx.configMode, 'explicit-register-option');
  assert.deepEqual(run.launcher.bubblewrap.identityWindow, {
    postSha256: run.launcher.bubblewrap.executableSha256,
    preSha256: run.launcher.bubblewrap.executableSha256,
    stable: true,
  });
});

test('the synthetic inputs are independently pinned and the real tsconfig has no extends chain', () => {
  const fixtureBytes = readFileSync(new URL('./fixtures/synthetic-probe.ts', import.meta.url));
  const tsconfigBytes = readFileSync(new URL('./fixtures/tsconfig.json', import.meta.url));
  const tsconfig = JSON.parse(tsconfigBytes.toString('utf8'));
  assert.equal(
    createHash('sha256').update(fixtureBytes).digest('hex'),
    '99e2e5d85d058cc357a030bde230267982a35306e67e22d75e4871d9d7062136'
  );
  assert.equal(
    createHash('sha256').update(tsconfigBytes).digest('hex'),
    '0947c5ba6762c9ec613c48b9fa55df51d6a4c72783b5870f4abaff0ee82aaac0'
  );
  assert.equal(Object.hasOwn(tsconfig, 'extends'), false);
  assert.equal(run.observation.tsconfig.extends, null);
});

test('the two isolation predicates remain blocked instead of being promoted', () => {
  assert.deepEqual(
    run.predicates.find(({ id }) => id === 'apparatusSourceClosureExact'),
    {
      blockers: [
        'successor-apparatus-and-accepted-h054-layer-source-lock-not-established',
        'path-execution-image-identity-not-atomically-bound',
      ],
      id: 'apparatusSourceClosureExact',
      status: 'blocked',
    }
  );
  assert.deepEqual(
    run.predicates.find(({ id }) => id === 'selectedNode22Exact'),
    {
      blockers: ['path-execution-image-identity-not-atomically-bound'],
      id: 'selectedNode22Exact',
      status: 'blocked',
    }
  );
  assert.deepEqual(
    run.predicates.find(({ id }) => id === 'emptyRootMountClosureExact'),
    {
      blockers: [
        'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
        'path-execution-image-identity-not-atomically-bound',
      ],
      id: 'emptyRootMountClosureExact',
      status: 'blocked',
    }
  );
  assert.deepEqual(
    run.predicates.find(({ id }) => id === 'isolatedNetworkNamespaceExact'),
    {
      blockers: [
        'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
      ],
      id: 'isolatedNetworkNamespaceExact',
      status: 'blocked',
    }
  );
  assert.deepEqual(
    run.predicates.find(({ id }) => id === 'failureBranchEvidenceMaterializable'),
    {
      blockers: ['failed-attempt-evidence-preservation-and-outcome-derivation-not-established'],
      id: 'failureBranchEvidenceMaterializable',
      status: 'blocked',
    }
  );
  assert.equal(
    run.predicates.find(({ id }) => id === 'independentVerifierReconstructs').status,
    'deferred'
  );
  assert.equal(run.predicates.find(({ id }) => id === 'allControlsFailClosed').status, 'deferred');
});

test('all 31 hostile controls are actually reapplied in memory and fail closed', () => {
  assert.deepEqual(
    verification.controls.map(({ id, expectedReasonCode }) => [id, expectedReasonCode]),
    EXPECTED_CONTROLS
  );
  assert.equal(
    verification.controls.every(
      (control) =>
        control.executionDisposition === 'reject-before-execution' &&
        control.mutationMode === 'in-memory-only' &&
        control.launchScope === 'positive-bubblewrap-boundary-only' &&
        control.observedReasonCode === control.expectedReasonCode &&
        control.passed === true &&
        control.positiveBoundaryLaunchCount === 0 &&
        control.status === 'independently-reapplied'
    ),
    true
  );
});

test('enable-tsconfig-fallback is an explicit effective-mode violation', () => {
  assert.equal(run.observation.tsx.configMode, 'explicit-register-option');
  const receipt = verification.controls.find(({ id }) => id === 'enable-tsconfig-fallback');
  assert.equal(receipt.observedReasonCode, 'loader-config-escape');
  assert.equal(receipt.positiveBoundaryLaunchCount, 0);
});

test('substitute-node22 mutates the exact executable layer and fails as runtime identity drift', () => {
  const nodeLayer = run.sourceClosure.layers.find(
    ({ id }) => id === 'runtime-file:/usr/bin/node-22'
  );
  assert.ok(nodeLayer);
  assert.equal(nodeLayer.entries.length, 1);
  assert.equal(nodeLayer.entries[0].logicalPath, '.');
  assert.equal(
    nodeLayer.entries[0].sha256,
    '1a1ebcd93dc90cf3e3dc37493e8efc04a1f60bddada1402453094214af03e33d'
  );
  const receipt = verification.controls.find(({ id }) => id === 'substitute-node22');
  assert.equal(receipt.observedReasonCode, 'runtime-identity-drift');
  assert.equal(receipt.positiveBoundaryLaunchCount, 0);
});

test('cross-layer mount targets are unique and their dedicated control fails closed', () => {
  const targets = run.sourceClosure.mounts.map(({ target }) => target);
  assert.equal(new Set(targets).size, targets.length);
  const receipt = verification.controls.find(
    ({ id }) => id === 'cross-layer-mount-target-collision'
  );
  assert.equal(receipt.observedReasonCode, 'layer-collision');
  assert.equal(receipt.positiveBoundaryLaunchCount, 0);
});

test('omit-import-target removes the exact reached TSX ESM API entry', () => {
  const tsxLayer = run.sourceClosure.layers.find(({ id }) => id === 'package/tsx@4.23.1');
  assert.ok(tsxLayer);
  assert.equal(
    tsxLayer.entries.some(
      ({ kind, logicalPath }) => kind === 'regular-file' && logicalPath === 'dist/esm/api/index.mjs'
    ),
    true
  );
  const receipt = verification.controls.find(({ id }) => id === 'omit-import-target');
  assert.equal(receipt.observedReasonCode, 'module-universe-incomplete');
  assert.equal(receipt.positiveBoundaryLaunchCount, 0);
});

test('dependency staleness mutates the exact reached Ajv entry and fails closed', () => {
  const ajvLayer = run.sourceClosure.layers.find(({ id }) => id === 'package/ajv@8.20.0');
  assert.ok(ajvLayer);
  assert.equal(
    ajvLayer.entries.some(
      ({ kind, logicalPath }) => kind === 'regular-file' && logicalPath === 'dist/ajv.js'
    ),
    true
  );
  const receipt = verification.controls.find(({ id }) => id === 'stale-ajv-entry');
  assert.equal(receipt.observedReasonCode, 'module-universe-incomplete');
  assert.equal(receipt.positiveBoundaryLaunchCount, 0);
});

test('representative independently rehashed tampering is rejected with precise reasons', () => {
  const stale = structuredClone(run);
  stale.anchors.trackedPredecessor.tree = '0'.repeat(40);
  assertInvalidReason(stale, 'temporal-anchor-stale');

  const authority = structuredClone(run);
  authority.authority = 'producer';
  assertInvalidReason(authority, 'authority-overclaim');

  const successor = structuredClone(run);
  successor.interpretation.successorState = {
    observation: 'universally-absent',
    syscallTrace: null,
    universalAbsenceProved: true,
  };
  assertInvalidReason(successor, 'successor-state-overclaim');
});

test('file verification rejects a non-content-addressed path before accepting semantics', () => {
  assert.throws(
    () => verifyNode22PreflightFile(fileURLToPath(new URL('./subject-lock.json', import.meta.url))),
    (error) =>
      error instanceof InvalidNode22PreflightEvidenceError &&
      error.reasonCode === 'raw-path-invalid'
  );
});

test('file verification requires a run-only content-addressed directory', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.match(source, /sameArray\(runDirectoryEntries, \['run\.json'\]\)/u);
  assert.match(source, /contains sidecars or unexpected entries/u);
});

test('producer raw preservation is fixed-path and policy-gated before mutation', () => {
  const source = readFileSync(new URL('./run.mjs', import.meta.url), 'utf8');
  const preserveStart = source.indexOf('export function preserveBoundaryEvidence(run)');
  const policyCheck = source.indexOf('verifyRawEvidencePolicy(repositoryRoot)', preserveStart);
  const firstDirectoryMutation = source.indexOf(
    'createOrInspectPrivateDirectory(evidencePaths.studyRoot',
    preserveStart
  );
  assert.ok(preserveStart >= 0);
  assert.ok(policyCheck > preserveStart);
  assert.ok(firstDirectoryMutation > policyCheck);
  assert.doesNotMatch(source, /export function boundaryEvidencePaths/u);
  assert.doesNotMatch(source, /export const BOUNDARY_EVIDENCE_PATHS/u);
  assert.match(source, /assertion\(arguments\.length === 1/u);
  assert.match(source, /canonicalJson\(afterEntries\) === canonicalJson\(\['run\.json'\]\)/u);
});

test('the explicit rerun performs exactly two positive launches and re-verifies post-state', () => {
  const receipt = rerunPositiveBoundary(run);
  assert.equal(receipt.launchCount, 2);
  assert.equal(receipt.byteIdentical, true);
  assert.equal(receipt.prePostBoundaryEquivalent, true);
  assert.equal(receipt.attempts[0].stdoutSha256, receipt.attempts[1].stdoutSha256);
  assert.equal(receipt.postVerification.semanticSha256, receipt.verification.semanticSha256);
  assert.equal(receipt.postVerification.sourceRootSha256, receipt.verification.sourceRootSha256);
  assert.deepEqual(receipt.postVerification.blockers, EXPECTED_BLOCKERS);
});
