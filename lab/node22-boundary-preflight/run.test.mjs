import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  EXPECTED_ENVIRONMENT,
  KNOWN_BLOCKERS,
  NODE_ARGV,
  SUBJECT,
  buildBoundaryEvidence,
  buildBwrapArgv,
  canonicalHash,
  canonicalJson,
  encodeBoundaryEvidence,
  preserveBoundaryEvidence,
  validateBoundaryEvidenceIdentity,
} from './run.mjs';

let evidencePromise;

function evidence() {
  evidencePromise ??= buildBoundaryEvidence();
  return evidencePromise;
}

function findPair(argv, flag, value) {
  for (let index = 0; index < argv.length - 1; index += 1) {
    if (argv[index] === flag && argv[index + 1] === value) return index;
  }
  return -1;
}

test('launcher is the exact empty-root, enumerated, read-only boundary', () => {
  const argv = buildBwrapArgv();
  assert.deepEqual(argv.slice(0, 12), [
    '--die-with-parent',
    '--new-session',
    '--unshare-all',
    '--unshare-user',
    '--disable-userns',
    '--assert-userns-disabled',
    '--hostname',
    'node22-preflight',
    '--cap-drop',
    'ALL',
    '--tmpfs',
    '/',
  ]);
  for (const forbidden of SUBJECT.executionContract.bubblewrapForbiddenFlags) {
    assert.equal(argv.includes(forbidden), false, forbidden);
  }
  assert.equal(findPair(argv, '--ro-bind', '/'), -1);
  assert.equal(findPair(argv, '--dir', '/dev') >= 0, true);
  assert.equal(findPair(argv, '--dir', '/proc') >= 0, true);
  assert.equal(findPair(argv, '--tmpfs', '/home') >= 0, true);
  assert.equal(findPair(argv, '--dir', '/home/probe') >= 0, true);
  assert.equal(findPair(argv, '--tmpfs', '/tmp') >= 0, true);

  const rootRemount = findPair(argv, '--remount-ro', '/');
  const homeRemount = findPair(argv, '--remount-ro', '/home');
  const tmpRemount = findPair(argv, '--remount-ro', '/tmp');
  const lastReadOnlyBind = argv.lastIndexOf('--ro-bind');
  assert.ok(homeRemount > lastReadOnlyBind);
  assert.ok(tmpRemount > homeRemount);
  assert.ok(rootRemount > tmpRemount);
  assert.equal(argv[rootRemount + 2], '--clearenv');

  const clearIndex = argv.indexOf('--clearenv');
  const chdirIndex = argv.indexOf('--chdir', clearIndex);
  const expectedEnvironmentSegment = Object.keys(EXPECTED_ENVIRONMENT)
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)))
    .flatMap((name) => ['--setenv', name, EXPECTED_ENVIRONMENT[name]]);
  assert.deepEqual(argv.slice(clearIndex + 1, chdirIndex), expectedEnvironmentSegment);
  assert.deepEqual(argv.slice(chdirIndex), ['--chdir', '/workspace', ...NODE_ARGV]);
});

test('two isolated attempts are byte-identical but the accepted blockers force inconclusive', async () => {
  const run = await evidence();
  assert.equal(run.attempts.length, 2);
  assert.equal(run.repeatability.attemptCount, 2);
  assert.equal(run.repeatability.byteIdentical, true);
  assert.equal(run.repeatability.semanticIdentical, true);
  assert.equal(run.attempts[0].stdoutSha256, run.attempts[1].stdoutSha256);
  assert.equal(
    run.attempts[0].observationSemanticSha256,
    run.attempts[1].observationSemanticSha256
  );
  assert.deepEqual(run.normalizations, []);
  assert.deepEqual(run.blockers, [...KNOWN_BLOCKERS]);
  assert.equal(run.blockers.length, 10);
  assert.equal(run.blockers.includes('path-execution-image-identity-not-atomically-bound'), true);
  assert.equal(
    run.blockers.includes(
      'successor-apparatus-and-accepted-h054-layer-source-lock-not-established'
    ),
    true
  );
  assert.equal(
    run.blockers.includes(
      'failed-attempt-evidence-preservation-and-outcome-derivation-not-established'
    ),
    true
  );
  assert.deepEqual(run.anchors.anchorResolver, {
    commands: {
      headCommit: [...SUBJECT.executionContract.anchorResolver.headCommitCommand],
      headTree: [...SUBJECT.executionContract.anchorResolver.headTreeCommand],
      predecessorManifest: [...SUBJECT.executionContract.anchorResolver.predecessorManifestCommand],
    },
    environment: { ...SUBJECT.executionContract.anchorResolver.environment },
    executablePath: SUBJECT.executionContract.anchorResolver.executable,
    executableSha256: SUBJECT.executionContract.anchorResolver.sha256,
    version: SUBJECT.executionContract.anchorResolver.version,
  });
  assert.deepEqual(run.outcome, {
    reason: 'known-boundary-completeness-blockers-remain',
    refutationEligible: false,
    status: 'inconclusive',
    supportEligible: false,
  });
  assert.deepEqual(run.humanReview, { accepted: null, required: true });
  assert.equal(run.authority, 'none');
  assert.equal(run.action, null);
  assert.equal(run.interpretation.adrCandidate, null);
  assert.deepEqual(run.interpretation.successorState, {
    observation: 'not-observed-within-nominated-boundary',
    syscallTrace: null,
    universalAbsenceProved: false,
  });
  assert.deepEqual(
    run.predicates.find(({ id }) => id === 'selectedNode22Exact'),
    {
      blockers: ['path-execution-image-identity-not-atomically-bound'],
      id: 'selectedNode22Exact',
      status: 'blocked',
    }
  );
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
    run.predicates.find(({ id }) => id === 'failureBranchEvidenceMaterializable'),
    {
      blockers: ['failed-attempt-evidence-preservation-and-outcome-derivation-not-established'],
      id: 'failureBranchEvidenceMaterializable',
      status: 'blocked',
    }
  );
});

test('the synthetic observation binds runtime, scoped TSX, Ajv, esbuild and absent case variant', async () => {
  const { observation } = await evidence();
  assert.equal(observation.schemaVersion, 'overlaykit-node22-boundary-preflight-observation/v1');
  assert.deepEqual(
    observation.runtime.sharedObjects,
    [...SUBJECT.executionContract.runtimeFileMounts.slice(1), 'linux-vdso.so.1'].sort(
      (left, right) => Buffer.from(left).compare(Buffer.from(right))
    )
  );
  assert.equal(
    observation.runtime.sharedObjectsSha256,
    canonicalHash(observation.runtime.sharedObjects)
  );
  assert.deepEqual(
    Object.fromEntries(
      Object.keys(SUBJECT.executionContract.expectedObservations.runtime).map((key) => [
        key,
        observation.runtime[key],
      ])
    ),
    SUBJECT.executionContract.expectedObservations.runtime
  );
  for (const name of ['tsx', 'ajv', 'esbuild']) {
    assert.deepEqual(observation[name], SUBJECT.executionContract.expectedObservations[name], name);
  }
  assert.equal(observation.tsx.configMode, 'explicit-register-option');
  assert.equal(Object.hasOwn(observation.tsconfig, 'extends'), true);
  assert.deepEqual(
    { extends: observation.tsconfig.extends },
    SUBJECT.executionContract.expectedObservations.tsconfig
  );
  assert.deepEqual(
    {
      locator: observation.fixture.path.slice('/workspace/'.length),
      sha256: observation.fixture.sha256,
    },
    SUBJECT.executionContract.expectedInputs.fixture
  );
  assert.deepEqual(
    {
      extends: observation.tsconfig.extends,
      locator: observation.tsconfig.path.slice('/workspace/'.length),
      sha256: observation.tsconfig.sha256,
    },
    SUBJECT.executionContract.expectedInputs.tsconfig
  );
  assert.deepEqual(observation.pathResolution, {
    caseVariantAbsent: true,
    caseVariantErrorCode: 'ENOENT',
    caseVariantPath: '/WORKSPACE',
  });
  assert.deepEqual(observation.scratch, { after: [], before: [] });
  assert.equal(observation.permissionEnvelope.fsWriteGlobal, false);
  assert.equal(observation.permissionEnvelope.addons, false);
});

test('source and mount closures are content-addressed and form a declaration bijection', async () => {
  const { launcher, sourceClosure } = await evidence();
  assert.equal(sourceClosure.stable, true);
  assert.equal(sourceClosure.preRootSha256, sourceClosure.postRootSha256);
  assert.equal(sourceClosure.rootSha256, sourceClosure.preRootSha256);
  assert.equal(sourceClosure.layers.length, sourceClosure.mounts.length);
  assert.equal(sourceClosure.layers.length, 25);
  const layerIds = new Set(sourceClosure.layers.map(({ id }) => id));
  assert.equal(layerIds.size, sourceClosure.layers.length);
  assert.deepEqual(
    sourceClosure.mounts.map(({ layerId }) => layerId),
    sourceClosure.layers.map(({ id }) => id)
  );

  for (const layer of sourceClosure.layers) {
    const { contentSha256, entryCount, ...body } = layer;
    assert.equal(contentSha256, canonicalHash(body), layer.id);
    assert.equal(entryCount, layer.entries.length, layer.id);
    const mount = sourceClosure.mounts.find(({ layerId }) => layerId === layer.id);
    assert.equal(mount.sourceContentSha256, layer.contentSha256, layer.id);
    assert.equal(mount.sourceLocator, layer.sourceLocator, layer.id);
    assert.equal(mount.sourceRealPath, layer.sourceRealPath, layer.id);
  }
  assert.equal(
    sourceClosure.rootSha256,
    canonicalHash({ layers: sourceClosure.layers, mounts: sourceClosure.mounts })
  );
  assert.equal(launcher.mountRosterSha256, canonicalHash(sourceClosure.mounts));
  assert.deepEqual(launcher.bubblewrap.identityWindow, {
    postSha256: SUBJECT.executionContract.launcher.sha256,
    preSha256: SUBJECT.executionContract.launcher.sha256,
    stable: true,
  });
  assert.equal(launcher.bubblewrap.executableSha256, launcher.bubblewrap.identityWindow.preSha256);

  const libz = sourceClosure.layers.find(
    ({ sourceLocator }) => sourceLocator === '/lib64/libz.so.1'
  );
  assert.deepEqual(libz.resolutionChain[0], {
    kind: 'symbolic-link',
    linkTarget: 'usr/lib64',
    mode: '0777',
    requestedPath: '/lib64',
    resolvedPath: '/usr/lib64',
  });
  assert.equal(libz.resolutionChain[1].requestedPath, '/lib64/libz.so.1');
  assert.equal(libz.resolutionChain[1].linkTarget, 'libz.so.1.3.1.zlib-ng');
});

test('producer preserves the dynamic control roster without self-approving verifier work', async () => {
  const { controls } = await evidence();
  assert.deepEqual(
    controls.map(({ id }) => id),
    SUBJECT.controlContract.map(({ id }) => id)
  );
  assert.equal(new Set(controls.map(({ id }) => id)).size, SUBJECT.controlContract.length);
  assert.equal(controls.length, 31);
  assert.equal(
    controls.some(({ id }) => id === 'stale-ajv-entry'),
    true
  );
  assert.equal(
    controls.some(({ id }) => id === 'layer-logical-path-collision'),
    true
  );
  assert.equal(
    controls.some(({ id }) => id === 'cross-layer-mount-target-collision'),
    true
  );
  for (const [index, control] of controls.entries()) {
    const expected = SUBJECT.controlContract[index];
    assert.equal(control.expectedReasonCode, expected.expectedReasonCode);
    assert.equal(control.observedReasonCode, null);
    assert.equal(control.executionDisposition, 'reject-before-execution');
    assert.equal(control.launchScope, 'positive-bubblewrap-boundary-only');
    assert.equal(control.mutationMode, 'in-memory-only');
    assert.equal(control.positiveBoundaryLaunchCount, 0);
    assert.equal(control.passed, null);
    assert.equal(control.status, 'deferred-to-independent-verifier');
  }
});

test('semantic identity excludes only the two derived identity fields', async () => {
  const run = await evidence();
  assert.equal(validateBoundaryEvidenceIdentity(run), run.semanticSha256);
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  assert.equal(run.semanticSha256, canonicalHash(body));
  assert.equal(run.runId, `node22-boundary-preflight-${run.semanticSha256.slice(0, 24)}`);
  const bytes = encodeBoundaryEvidence(run);
  assert.equal(bytes.at(-1), 0x0a);
  assert.deepEqual(JSON.parse(bytes.toString('utf8')), JSON.parse(canonicalJson(run)));
});

test('raw writer source is fixed-path, exclusive, no-follow, private and owner-bound', () => {
  const source = readFileSync(new URL('./run.mjs', import.meta.url), 'utf8');
  const preserveStart = source.indexOf('export function preserveBoundaryEvidence(run)');
  const policyCheck = source.indexOf('verifyRawEvidencePolicy(repositoryRoot)', preserveStart);
  const firstDirectoryMutation = source.indexOf(
    'createOrInspectPrivateDirectory(evidencePaths.studyRoot',
    preserveStart
  );
  assert.equal(preserveBoundaryEvidence.length, 1);
  assert.ok(preserveStart >= 0);
  assert.ok(policyCheck > preserveStart);
  assert.ok(firstDirectoryMutation > policyCheck);
  assert.doesNotMatch(source, /export function boundaryEvidencePaths/u);
  assert.doesNotMatch(source, /export const BOUNDARY_EVIDENCE_PATHS/u);
  assert.deepEqual(SUBJECT.rawEvidencePolicy, {
    evidenceRootLocator: 'artifacts/',
    gitignore: {
      locator: '.gitignore',
      rawSha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
      requiredPattern: 'artifacts/',
    },
    mustRemainIgnored: true,
  });
  assert.match(source, /readStableRegularFile\(gitignorePath\)/u);
  assert.match(source, /assertion\(beforeEntries\.length === 0/u);
  assert.match(source, /canonicalJson\(afterEntries\) === canonicalJson\(\['run\.json'\]\)/u);
  assert.match(source, /constants\.O_EXCL/u);
  assert.match(source, /constants\.O_NOFOLLOW/u);
  assert.match(source, /mode: 0o700/u);
  assert.match(source, /0o600/u);
  assert.match(source, /metadata\.uid === process\.getuid\(\)/u);
  assert.match(source, /args\[0\] === '--write'/u);
  assert.doesNotMatch(source, /--output/u);
});

test('probe source admits only the synthetic scoped import surface', () => {
  const source = readFileSync(new URL('./probe.mjs', import.meta.url), 'utf8');
  assert.match(source, /await import\('tsx\/esm\/api'\)/u);
  assert.match(source, /namespace: FIXED_NAMESPACE/u);
  assert.match(source, /onImport\(url\)/u);
  assert.match(source, /await registration\.import\(FIXTURE_PATH, import\.meta\.url\)/u);
  assert.match(source, /await registration\.unregister\(\)/u);
  assert.doesNotMatch(source, /\btsImport\s*\(/u);
  const staticSpecifiers = [...source.matchAll(/^import .* from '([^']+)';$/gmu)].map(
    (match) => match[1]
  );
  assert.ok(staticSpecifiers.every((specifier) => specifier.startsWith('node:')));
  assert.equal(source.includes('/proc/'), false);
  assert.equal(source.includes('/dev/'), false);
});
