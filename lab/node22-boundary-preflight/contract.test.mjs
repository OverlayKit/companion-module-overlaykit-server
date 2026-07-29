import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const subject = JSON.parse(readFileSync(new URL('./subject-lock.json', import.meta.url), 'utf8'));

test('the temporal boundary preserves the accepted predecessor and prospective selection', () => {
  assert.equal(
    subject.temporalBoundary.trackedPredecessor.commit,
    'bb6ce5db53541a7926eb74b3c722fa039ca9dabd'
  );
  assert.equal(
    subject.temporalBoundary.trackedPredecessor.tree,
    '823796b0c9f509cf4ed35b9febeb71c284626036'
  );
  assert.equal(
    subject.temporalBoundary.acceptedH054.rawSha256,
    '250e6115b9e9dc6d9e750788c16626657feca5577c102b84a48e4fb4bf2444f2'
  );
  assert.equal(subject.temporalBoundary.acceptedH054.preserveByteIdentical, true);
  assert.equal(subject.temporalBoundary.prospectiveRuntimeSelection.id, 'node22');
  assert.equal(subject.temporalBoundary.prospectiveRuntimeSelection.rewritesAcceptedH054, false);
});

test('the launcher contract is an empty-root read-only allowlist', () => {
  const contract = subject.executionContract;
  assert.deepEqual(contract.normalizations, []);
  assert.equal(contract.anchorResolver.executable, '/usr/bin/git');
  assert.equal(
    contract.anchorResolver.sha256,
    '8d8d470218586c27909c9b6ae77d18df32a9e05e725044ae2052d60254791c26'
  );
  assert.equal(contract.launcher.executable, '/usr/bin/bwrap');
  assert.equal(
    contract.launcher.sha256,
    'b3708edde1d80e5f570f2e15d692e49c1d96dc8f411896c60abd489c13368390'
  );
  assert.equal(contract.unexpectedArgumentsRejected, true);
  assert.equal(contract.bubblewrapRequiredFlags.includes('--unshare-all'), true);
  assert.equal(contract.bubblewrapRequiredFlags.includes('--unshare-user'), true);
  assert.equal(contract.bubblewrapRequiredFlags.includes('--disable-userns'), true);
  assert.equal(contract.bubblewrapRequiredFlags.includes('--assert-userns-disabled'), true);
  assert.equal(contract.bubblewrapRequiredFlags.includes('--remount-ro'), true);
  assert.equal(contract.bubblewrapForbiddenFlags.includes('--share-net'), true);
  assert.equal(contract.bubblewrapForbiddenFlags.includes('--proc'), true);
  assert.equal(contract.bubblewrapForbiddenFlags.includes('--dev'), true);
  assert.equal(contract.nodeArgv.includes('--allow-fs-write'), false);
  assert.equal(contract.nodeArgv.includes('--no-addons'), true);
  assert.equal(contract.nodeArgv.includes('--allow-child-process'), true);
  assert.equal(contract.nodeArgv.includes('--allow-worker'), true);

  const sources = contract.readOnlyDirectoryMounts.map(({ source }) => source);
  const targets = contract.readOnlyDirectoryMounts.map(({ target }) => target);
  assert.equal(new Set(sources).size, sources.length);
  assert.equal(new Set(targets).size, targets.length);
  assert.equal(sources.includes('/'), false);
  assert.equal(targets.includes('/'), false);
  assert.equal(contract.runtimeFileMounts.length, 16);
  assert.equal(new Set(contract.runtimeFileMounts).size, 16);
});

test('the environment is exact and excludes ambient selectors', () => {
  const environment = subject.executionContract.environment;
  assert.deepEqual(Object.keys(environment).sort(), [
    'ESBUILD_BINARY_PATH',
    'ESBUILD_WORKER_THREADS',
    'HOME',
    'LANG',
    'LC_ALL',
    'NODE_DISABLE_COLORS',
    'NODE_DISABLE_COMPILE_CACHE',
    'NO_COLOR',
    'PATH',
    'PWD',
    'TERM',
    'TMPDIR',
    'TSX_DISABLE_CACHE',
    'TSX_TSCONFIG_PATH',
    'TZ',
    'XDG_CACHE_HOME',
  ]);
  for (const absent of [
    'LD_AUDIT',
    'LD_LIBRARY_PATH',
    'LD_PRELOAD',
    'NODE_OPTIONS',
    'NODE_PATH',
    'NODE_V8_COVERAGE',
    'OPENSSL_CONF',
  ]) {
    assert.equal(Object.hasOwn(environment, absent), false);
  }
});

test('known blockers dominate the narrow compatibility observations', () => {
  assert.deepEqual(subject.hypothesis.outcomePrecedence, [
    'invalid',
    'inconclusive',
    'refuted',
    'supported',
  ]);
  assert.deepEqual(subject.executionContract.normalizations, []);
  assert.equal(subject.knownBlockingUnknowns.length, 10);
  assert.equal(
    subject.knownBlockingUnknowns.includes('path-execution-image-identity-not-atomically-bound'),
    true
  );
  assert.equal(
    subject.knownBlockingUnknowns.includes(
      'successor-apparatus-and-accepted-h054-layer-source-lock-not-established'
    ),
    true
  );
  assert.equal(
    subject.knownBlockingUnknowns.includes(
      'failed-attempt-evidence-preservation-and-outcome-derivation-not-established'
    ),
    true
  );
  assert.equal(subject.requiredPredicates.includes('exhaustiveOpenFileAndModuleClosure'), true);
  assert.equal(subject.requiredPredicates.includes('effectiveSyscallClosure'), true);
  assert.equal(subject.requiredPredicates.includes('nativeAndLateLoadedObjectClosure'), true);
  assert.equal(subject.requiredPredicates.includes('failureBranchEvidenceMaterializable'), true);
});

test('hostile controls are unique and must be rejected before execution', () => {
  const controls = subject.controlContract;
  assert.equal(controls.length, 31);
  assert.equal(new Set(controls.map(({ id }) => id)).size, controls.length);
  assert.equal(
    controls.every(({ expectedReasonCode }) => expectedReasonCode.length > 0),
    true
  );
  assert.deepEqual(
    controls.find(({ id }) => id === 'stale-ajv-entry'),
    {
      expectedReasonCode: 'module-universe-incomplete',
      id: 'stale-ajv-entry',
    }
  );
  assert.deepEqual(
    controls
      .filter(({ id }) =>
        ['layer-logical-path-collision', 'cross-layer-mount-target-collision'].includes(id)
      )
      .map(({ expectedReasonCode, id }) => ({ expectedReasonCode, id })),
    [
      {
        expectedReasonCode: 'layer-collision',
        id: 'layer-logical-path-collision',
      },
      {
        expectedReasonCode: 'layer-collision',
        id: 'cross-layer-mount-target-collision',
      },
    ]
  );
  assert.equal(
    subject.controlExecutionPolicy.hostileBoundaryMutationDisposition,
    'reject-before-execution'
  );
  assert.equal(subject.controlExecutionPolicy.weakenedSandboxMayLaunch, false);
  assert.equal(subject.controlExecutionPolicy.forbiddenSubjectMayBeImportedOrExecuted, false);
  assert.equal(subject.controlExecutionPolicy.onlyPositiveBoundaryMayLaunch, true);
  assert.equal(
    subject.controlExecutionPolicy.launchCountScope,
    'positive-bubblewrap-boundary-only'
  );
});

test('the synthetic observations are exact and non-normative', () => {
  const expected = subject.executionContract.expectedObservations;
  assert.deepEqual(subject.executionContract.expectedInputs, {
    fixture: {
      locator: 'lab/node22-boundary-preflight/fixtures/synthetic-probe.ts',
      sha256: '99e2e5d85d058cc357a030bde230267982a35306e67e22d75e4871d9d7062136',
    },
    tsconfig: {
      extends: null,
      locator: 'lab/node22-boundary-preflight/fixtures/tsconfig.json',
      sha256: '0947c5ba6762c9ec613c48b9fa55df51d6a4c72783b5870f4abaff0ee82aaac0',
    },
  });
  assert.equal(expected.runtime.version, 'v22.22.2');
  assert.equal(expected.tsx.namespace, 'node22-boundary-preflight');
  assert.equal(expected.tsx.configMode, 'explicit-register-option');
  assert.equal(expected.tsx.answer, 42);
  assert.equal(expected.ajv.validAccepted, true);
  assert.equal(expected.ajv.invalidAccepted, false);
  assert.equal(expected.tsconfig.extends, null);
  assert.equal(
    expected.esbuild.codeSha256,
    '4c00f4280b91ec851a19f0f046b4f05cafcc107399f03de18c4f6a9c8e30b197'
  );
  assert.equal(subject.normative, false);
  assert.equal(subject.agent.authority, 'none');
  assert.equal(subject.agent.action, null);
});

test('raw evidence remains pinned to the exact ignored artifacts root', () => {
  assert.deepEqual(subject.rawEvidencePolicy, {
    evidenceRootLocator: 'artifacts/',
    gitignore: {
      locator: '.gitignore',
      rawSha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
      requiredPattern: 'artifacts/',
    },
    mustRemainIgnored: true,
  });
});
