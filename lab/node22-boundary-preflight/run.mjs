import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const APPARATUS_ROOT = path.dirname(fileURLToPath(import.meta.url));
export const REPOSITORY_ROOT = realpathSync(path.resolve(APPARATUS_ROOT, '../..'));
const SUBJECT_PATH = path.join(APPARATUS_ROOT, 'subject-lock.json');
const SUBJECT_LOCATOR = 'lab/node22-boundary-preflight/subject-lock.json';
const CHG0036_LOCATOR = '.overlaykit/governance/changes/CHG-0036.json';
const MANIFEST_LOCATOR = '.overlaykit/governance/manifest.json';

export const SUBJECT = JSON.parse(readFileSync(SUBJECT_PATH, 'utf8'));
const CONTRACT = SUBJECT.executionContract;

export const EXPECTED_ENVIRONMENT = Object.freeze({ ...CONTRACT.environment });
export const KNOWN_BLOCKERS = Object.freeze([...SUBJECT.knownBlockingUnknowns]);
export const NODE_ARGV = Object.freeze([...CONTRACT.nodeArgv]);

const SCHEMA_VERSION = 'overlaykit-node22-boundary-preflight-run/v1';
const OBSERVATION_SCHEMA_VERSION = 'overlaykit-node22-boundary-preflight-observation/v1';
const EVIDENCE_RELATIVE_ROOT = 'artifacts/node22-boundary-preflight';
const H054_RUN_LOCATOR = `artifacts/h054/runs/${SUBJECT.temporalBoundary.acceptedH054.semanticSha256}/run.json`;
const LOCKED_EXPECTED_INPUTS = Object.freeze({
  fixture: Object.freeze({
    locator: 'lab/node22-boundary-preflight/fixtures/synthetic-probe.ts',
    sha256: '99e2e5d85d058cc357a030bde230267982a35306e67e22d75e4871d9d7062136',
  }),
  tsconfig: Object.freeze({
    extends: null,
    locator: 'lab/node22-boundary-preflight/fixtures/tsconfig.json',
    sha256: '0947c5ba6762c9ec613c48b9fa55df51d6a4c72783b5870f4abaff0ee82aaac0',
  }),
});
const LOCKED_RAW_EVIDENCE_POLICY = Object.freeze({
  evidenceRootLocator: 'artifacts/',
  gitignore: Object.freeze({
    locator: '.gitignore',
    rawSha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
    requiredPattern: 'artifacts/',
  }),
  mustRemainIgnored: true,
});

function assertion(condition, reasonCode, detail) {
  if (!condition) {
    throw new Error(`NODE22_BOUNDARY_PREFLIGHT_REFUSED:${reasonCode}:${detail}`);
  }
}

function bytewise(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalValue(value, seen = new Set()) {
  if (Array.isArray(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid', 'cycle');
    seen.add(value);
    const result = value.map((entry) => canonicalValue(entry, seen));
    seen.delete(value);
    return result;
  }
  if (isPlainObject(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid', 'cycle');
    seen.add(value);
    const result = {};
    for (const key of Object.keys(value).sort(bytewise)) {
      result[key] = canonicalValue(value[key], seen);
    }
    seen.delete(value);
    return result;
  }
  assertion(
    value === null || ['boolean', 'number', 'string'].includes(typeof value),
    'canonical-value-invalid',
    String(value)
  );
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function canonicalPrettyJson(value) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function governanceCanonicalHash(value) {
  function canonicalize(entry) {
    if (Array.isArray(entry)) return entry.map((item) => canonicalize(item));
    if (isPlainObject(entry)) {
      return Object.fromEntries(
        Object.keys(entry)
          .sort((left, right) => left.localeCompare(right))
          .map((key) => [key, canonicalize(entry[key])])
      );
    }
    assertion(
      entry === null || ['boolean', 'number', 'string'].includes(typeof entry),
      'current-governance-anchor-invalid',
      'unsupported-manifest-value'
    );
    return entry;
  }
  return sha256(Buffer.from(JSON.stringify(canonicalize(value)), 'utf8'));
}

function modeString(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, '0');
}

function readStableRegularFile(absolutePath) {
  const descriptor = openSync(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    assertion(before.isFile(), 'path-resolution-invalid', `${absolutePath}:not-regular`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    assertion(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        before.mtimeMs === after.mtimeMs &&
        bytes.length === after.size,
      'source-changed-during-read',
      absolutePath
    );
    return { bytes, metadata: after };
  } finally {
    closeSync(descriptor);
  }
}

function describeRegularFile(logicalPath, absolutePath) {
  const { bytes, metadata } = readStableRegularFile(absolutePath);
  return {
    byteLength: bytes.length,
    kind: 'regular-file',
    logicalPath,
    mode: modeString(metadata),
    sha256: sha256(bytes),
  };
}

function describeDirectoryEntries(sourcePath) {
  const entries = [];

  function visit(relativePath) {
    const absolutePath =
      relativePath === '.' ? sourcePath : path.join(sourcePath, ...relativePath.split('/'));
    const metadata = lstatSync(absolutePath);
    if (metadata.isSymbolicLink()) {
      const linkTarget = readlinkSync(absolutePath, 'utf8');
      entries.push({
        kind: 'symbolic-link',
        linkTarget,
        logicalPath: relativePath,
        mode: modeString(metadata),
      });
      assertion(false, 'path-resolution-invalid', `${relativePath}:symbolic-link`);
    }
    if (metadata.isDirectory()) {
      entries.push({
        kind: 'directory',
        logicalPath: relativePath,
        mode: modeString(metadata),
      });
      const names = readdirSync(absolutePath, { encoding: 'utf8' }).sort(bytewise);
      for (const name of names) {
        const child = relativePath === '.' ? name : `${relativePath}/${name}`;
        visit(child);
      }
      return;
    }
    if (metadata.isFile()) {
      entries.push(describeRegularFile(relativePath, absolutePath));
      return;
    }
    assertion(false, 'path-resolution-invalid', `${relativePath}:unsupported-type`);
  }

  visit('.');
  return entries.sort((left, right) => bytewise(left.logicalPath, right.logicalPath));
}

function layerWithIdentity(body) {
  return {
    ...body,
    contentSha256: canonicalHash(body),
    entryCount: body.entries.length,
  };
}

function describeDirectoryLayer(declaration) {
  const absoluteSource = path.resolve(REPOSITORY_ROOT, declaration.source);
  const sourceMetadata = lstatSync(absoluteSource);
  assertion(
    sourceMetadata.isDirectory() && !sourceMetadata.isSymbolicLink(),
    'path-resolution-invalid',
    declaration.source
  );
  const sourceRealPath = realpathSync(absoluteSource);
  return layerWithIdentity({
    entries: describeDirectoryEntries(sourceRealPath),
    id: declaration.layerId,
    kind: 'directory-tree',
    sourceLocator: declaration.source,
    sourceRealPath,
  });
}

function describeRuntimeLayer(sourceLocator) {
  const sourceRealPath = realpathSync(sourceLocator);
  const body = {
    entries: [describeRegularFile('.', sourceRealPath)],
    id: `runtime-file:${sourceLocator}`,
    kind: 'runtime-file',
    resolutionChain: runtimeResolutionChain(sourceLocator),
    sourceLocator,
    sourceRealPath,
  };
  return layerWithIdentity(body);
}

function runtimeResolutionChain(sourceLocator) {
  assertion(path.isAbsolute(sourceLocator), 'path-resolution-invalid', sourceLocator);
  const chain = [];
  const components = sourceLocator.split('/').filter(Boolean);
  let requestedPath = '';
  let resolvedParent = '/';
  for (const component of components) {
    requestedPath = `${requestedPath}/${component}`;
    const candidate = path.join(resolvedParent, component);
    const metadata = lstatSync(candidate);
    if (metadata.isSymbolicLink()) {
      const resolvedPath = realpathSync(candidate);
      chain.push({
        kind: 'symbolic-link',
        linkTarget: readlinkSync(candidate, 'utf8'),
        mode: modeString(metadata),
        requestedPath,
        resolvedPath,
      });
      resolvedParent = resolvedPath;
      continue;
    }
    resolvedParent = candidate;
  }
  assertion(
    resolvedParent === realpathSync(sourceLocator),
    'path-resolution-invalid',
    `${sourceLocator}:chain`
  );
  return chain;
}

export const MOUNT_DECLARATIONS = Object.freeze([
  ...CONTRACT.runtimeFileMounts.map((source) =>
    Object.freeze({
      access: 'read-only',
      kind: 'runtime-file',
      layerId: `runtime-file:${source}`,
      source,
      target: source,
    })
  ),
  ...CONTRACT.readOnlyDirectoryMounts.map(({ layerId, source, target }) =>
    Object.freeze({
      access: 'read-only',
      kind: 'directory-tree',
      layerId,
      source,
      target,
    })
  ),
]);

function mountsFromLayers(layers) {
  const layersById = new Map(layers.map((layer) => [layer.id, layer]));
  return MOUNT_DECLARATIONS.map((declaration) => {
    const layer = layersById.get(declaration.layerId);
    assertion(layer !== undefined, 'mount-layer-missing', declaration.layerId);
    return {
      access: declaration.access,
      kind: declaration.kind,
      layerId: declaration.layerId,
      sourceContentSha256: layer.contentSha256,
      sourceLocator: declaration.source,
      sourceRealPath: layer.sourceRealPath,
      target: declaration.target,
    };
  });
}

export function buildSourceClosure() {
  const layers = [
    ...CONTRACT.runtimeFileMounts.map((source) => describeRuntimeLayer(source)),
    ...CONTRACT.readOnlyDirectoryMounts.map((declaration) => describeDirectoryLayer(declaration)),
  ];
  const mounts = mountsFromLayers(layers);
  const rootSha256 = canonicalHash({ layers, mounts });
  return { layers, mounts, rootSha256 };
}

function exactSpawn(executable, argv, options = {}) {
  const result = spawnSync(executable, argv, {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: {},
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  assertion(result.error === undefined, 'launcher-execution-failed', result.error?.message ?? '');
  return result;
}

function gitBytes(argv) {
  const resolver = CONTRACT.anchorResolver;
  const allowed = [
    resolver.headCommitCommand,
    resolver.headTreeCommand,
    resolver.predecessorManifestCommand,
  ];
  assertion(
    allowed.some((command) => canonicalJson(command) === canonicalJson(argv)),
    'anchor-resolver-command-drift',
    canonicalHash(argv)
  );
  const result = spawnSync(resolver.executable, argv, {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: { ...resolver.environment },
    maxBuffer: 16 * 1024 * 1024,
  });
  assertion(result.error === undefined, 'temporal-anchor-unavailable', result.error?.message ?? '');
  assertion(
    result.status === 0 && result.signal === null,
    'temporal-anchor-unavailable',
    result.stderr.toString('utf8')
  );
  return result.stdout;
}

function verifyAnchorResolver() {
  const resolver = CONTRACT.anchorResolver;
  const executableBytes = readStableRegularFile(resolver.executable).bytes;
  assertion(
    sha256(executableBytes) === resolver.sha256,
    'anchor-resolver-identity-drift',
    sha256(executableBytes)
  );
  const version = spawnSync(resolver.executable, ['--version'], {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: { ...resolver.environment },
    maxBuffer: 1024 * 1024,
  });
  assertion(
    version.error === undefined &&
      version.status === 0 &&
      version.signal === null &&
      version.stderr.length === 0 &&
      version.stdout.toString('utf8').trim() === resolver.version,
    'anchor-resolver-identity-drift',
    version.stdout?.toString('utf8').trim() ?? version.error?.message ?? ''
  );
  return {
    commands: {
      headCommit: [...resolver.headCommitCommand],
      headTree: [...resolver.headTreeCommand],
      predecessorManifest: [...resolver.predecessorManifestCommand],
    },
    environment: { ...resolver.environment },
    executablePath: resolver.executable,
    executableSha256: resolver.sha256,
    version: resolver.version,
  };
}

function buildAnchors() {
  const anchorResolver = verifyAnchorResolver();
  const tracked = SUBJECT.temporalBoundary.trackedPredecessor;
  const commit = gitBytes(CONTRACT.anchorResolver.headCommitCommand).toString('utf8').trim();
  const tree = gitBytes(CONTRACT.anchorResolver.headTreeCommand).toString('utf8').trim();
  assertion(commit === tracked.commit, 'temporal-anchor-stale', commit);
  assertion(tree === tracked.tree, 'temporal-anchor-stale', tree);

  const predecessorManifest = gitBytes(CONTRACT.anchorResolver.predecessorManifestCommand);
  assertion(
    sha256(predecessorManifest) === tracked.predecessorManifestRawSha256,
    'temporal-anchor-stale',
    'predecessor-manifest'
  );

  const planBytes = readStableRegularFile(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/plan.json')
  ).bytes;
  const chg0035Bytes = readStableRegularFile(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0035.json')
  ).bytes;
  assertion(sha256(planBytes) === tracked.planRawSha256, 'temporal-anchor-stale', 'plan');
  assertion(sha256(chg0035Bytes) === tracked.chg0035RawSha256, 'temporal-anchor-stale', 'chg0035');

  const h054Path = path.join(REPOSITORY_ROOT, H054_RUN_LOCATOR);
  const h054Bytes = readStableRegularFile(h054Path).bytes;
  const acceptedH054 = SUBJECT.temporalBoundary.acceptedH054;
  assertion(sha256(h054Bytes) === acceptedH054.rawSha256, 'accepted-h054-drift', H054_RUN_LOCATOR);
  const h054 = JSON.parse(h054Bytes.toString('utf8'));
  assertion(h054.semanticSha256 === acceptedH054.semanticSha256, 'accepted-h054-drift', 'semantic');

  const subjectBytes = readStableRegularFile(SUBJECT_PATH).bytes;
  const chg0036Bytes = readStableRegularFile(path.join(REPOSITORY_ROOT, CHG0036_LOCATOR)).bytes;
  const manifestBytes = readStableRegularFile(path.join(REPOSITORY_ROOT, MANIFEST_LOCATOR)).bytes;
  const chg0036 = JSON.parse(chg0036Bytes.toString('utf8'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const { contentHash: _manifestContentHash, ...manifestBody } = manifest;
  assertion(
    chg0036.id === 'CHG-0036' &&
      chg0036.status === 'proposed' &&
      manifest.changes?.['CHG-0036'] === sha256(chg0036Bytes) &&
      manifest.contentHash === governanceCanonicalHash(manifestBody),
    'current-governance-anchor-invalid',
    'CHG-0036'
  );
  return {
    acceptedH054: {
      classification: acceptedH054.classification,
      locator: H054_RUN_LOCATOR,
      rawSha256: acceptedH054.rawSha256,
      semanticSha256: acceptedH054.semanticSha256,
    },
    anchorResolver,
    governance: {
      chg0035RawSha256: sha256(chg0035Bytes),
      chg0036: {
        locator: CHG0036_LOCATOR,
        manifestEntry: manifest.changes['CHG-0036'],
        rawSha256: sha256(chg0036Bytes),
        status: chg0036.status,
      },
      currentManifest: {
        changeEntry: manifest.changes['CHG-0036'],
        contentHash: manifest.contentHash,
        locator: MANIFEST_LOCATOR,
        rawSha256: sha256(manifestBytes),
      },
      planHash: tracked.planHash,
      planRawSha256: sha256(planBytes),
      predecessorManifestRawSha256: sha256(predecessorManifest),
    },
    subject: {
      locator: SUBJECT_LOCATOR,
      rawSha256: sha256(subjectBytes),
    },
    trackedPredecessor: {
      commit,
      tree,
    },
  };
}

function assertExecutionContract() {
  assertion(
    SUBJECT.schemaVersion === 'overlaykit-node22-boundary-preflight-subject/v1' &&
      SUBJECT.id === 'NODE22-BOUNDARY-PREFLIGHT-001' &&
      SUBJECT.normative === false,
    'subject-contract-invalid',
    SUBJECT.id
  );
  assertion(
    canonicalJson(CONTRACT.normalizations) === '[]',
    'normalization-policy-drift',
    canonicalJson(CONTRACT.normalizations)
  );
  assertion(
    canonicalJson(CONTRACT.expectedInputs) === canonicalJson(LOCKED_EXPECTED_INPUTS) &&
      CONTRACT.moduleResolution.fixture ===
        `/workspace/${LOCKED_EXPECTED_INPUTS.fixture.locator}` &&
      CONTRACT.moduleResolution.tsxConfig ===
        `/workspace/${LOCKED_EXPECTED_INPUTS.tsconfig.locator}`,
    'execution-contract-drift',
    'expected-input-lock'
  );
  assertion(
    CONTRACT.seccompPolicy === null && CONTRACT.expectedAttemptCount === 2,
    'execution-contract-drift',
    'cardinality-or-seccomp'
  );
  assertion(
    canonicalJson(KNOWN_BLOCKERS) === canonicalJson(SUBJECT.knownBlockingUnknowns),
    'outcome-policy-violation',
    'blockers'
  );
  assertion(
    REPOSITORY_ROOT === CONTRACT.launcher.hostCwd,
    'launcher-host-cwd-drift',
    REPOSITORY_ROOT
  );
}

function verifyExpectedInputs() {
  for (const [name, expected] of Object.entries(LOCKED_EXPECTED_INPUTS)) {
    const absolutePath = path.resolve(REPOSITORY_ROOT, expected.locator);
    const relativePath = path.relative(REPOSITORY_ROOT, absolutePath);
    assertion(
      relativePath === expected.locator &&
        !relativePath.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relativePath),
      'apparatus-source-set-drift',
      `${name}:locator`
    );
    const bytes = readStableRegularFile(absolutePath).bytes;
    const observedSha256 = sha256(bytes);
    assertion(
      observedSha256 === expected.sha256,
      name === 'tsconfig' ? 'loader-config-escape' : 'apparatus-source-set-drift',
      `${name}:${observedSha256}`
    );
  }
}

export function buildBwrapArgv() {
  assertExecutionContract();
  const argv = [
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
  ];

  for (const directory of CONTRACT.emptyDirectories) {
    argv.push('--dir', directory);
  }
  for (const privateMount of CONTRACT.readOnlyPrivateMounts) {
    argv.push(...privateMount.create);
    for (const child of privateMount.childrenBeforeRemount) {
      argv.push(...child);
    }
  }
  for (const source of CONTRACT.runtimeFileMounts) {
    argv.push('--ro-bind', source, source);
  }
  for (const { source, target } of CONTRACT.readOnlyDirectoryMounts) {
    argv.push('--ro-bind', source, target);
  }
  for (const privateMount of CONTRACT.readOnlyPrivateMounts) {
    argv.push(...privateMount.remount);
  }
  argv.push('--remount-ro', '/', '--clearenv');
  for (const name of Object.keys(EXPECTED_ENVIRONMENT).sort(bytewise)) {
    argv.push('--setenv', name, EXPECTED_ENVIRONMENT[name]);
  }
  argv.push('--chdir', '/workspace', ...NODE_ARGV);

  const forbidden = new Set(CONTRACT.bubblewrapForbiddenFlags);
  assertion(
    argv.every((argument) => !forbidden.has(argument)),
    'mount-boundary-broadened',
    'forbidden-flag'
  );
  const rootRemountIndex = argv.lastIndexOf('/');
  const lastMountIndex = Math.max(
    argv.lastIndexOf('--ro-bind'),
    argv.lastIndexOf('--tmpfs'),
    argv.lastIndexOf('--dir')
  );
  assertion(rootRemountIndex > lastMountIndex, 'mount-boundary-broadened', 'root-remount-order');
  return argv;
}

function validateObservation(observation) {
  assertion(
    observation.schemaVersion === OBSERVATION_SCHEMA_VERSION,
    'probe-observation-invalid',
    'schema'
  );
  for (const [name, expected] of Object.entries(CONTRACT.expectedObservations)) {
    const observed = observation[name];
    if (name === 'runtime') {
      const identity = Object.fromEntries(
        Object.keys(expected).map((key) => [key, observed?.[key]])
      );
      assertion(
        canonicalJson(identity) === canonicalJson(expected),
        'runtime-identity-drift',
        canonicalHash(identity)
      );
      continue;
    }
    if (name === 'tsconfig') {
      assertion(
        observed !== null &&
          typeof observed === 'object' &&
          Object.hasOwn(observed, 'extends') &&
          canonicalJson({ extends: observed.extends }) === canonicalJson(expected),
        'loader-config-escape',
        canonicalHash(observed ?? null)
      );
      continue;
    }
    assertion(
      canonicalJson(observed) === canonicalJson(expected),
      `synthetic-${name}-observation-failed`,
      canonicalHash(observed ?? null)
    );
  }
  assertion(
    canonicalJson(observation.environment) === canonicalJson(EXPECTED_ENVIRONMENT),
    'environment-closure-drift',
    canonicalHash(observation.environment)
  );
  assertion(
    canonicalJson(observation.invocation.execArgv) === canonicalJson(NODE_ARGV.slice(1, -1)),
    'permission-envelope-drift',
    canonicalHash(observation.invocation.execArgv)
  );
  assertion(
    observation.permissionEnvelope.fsWriteGlobal === false &&
      observation.permissionEnvelope.addons === false &&
      observation.permissionEnvelope.worker === true &&
      observation.permissionEnvelope.child === true &&
      observation.pathResolution.caseVariantAbsent === true &&
      observation.pathResolution.caseVariantErrorCode === 'ENOENT' &&
      observation.pathResolution.caseVariantPath === '/WORKSPACE',
    'permission-envelope-drift',
    canonicalHash(observation.permissionEnvelope)
  );
  assertion(
    canonicalJson(observation.scratch) === canonicalJson({ after: [], before: [] }),
    'mutable-state-observed',
    canonicalHash(observation.scratch)
  );
  assertion(
    observation.fixture?.path === `/workspace/${LOCKED_EXPECTED_INPUTS.fixture.locator}` &&
      observation.fixture?.sha256 === LOCKED_EXPECTED_INPUTS.fixture.sha256,
    'apparatus-source-set-drift',
    canonicalHash(observation.fixture ?? null)
  );
  assertion(
    observation.tsconfig?.path === `/workspace/${LOCKED_EXPECTED_INPUTS.tsconfig.locator}` &&
      observation.tsconfig?.sha256 === LOCKED_EXPECTED_INPUTS.tsconfig.sha256 &&
      observation.tsconfig?.extends === LOCKED_EXPECTED_INPUTS.tsconfig.extends,
    'loader-config-escape',
    canonicalHash(observation.tsconfig ?? null)
  );
  assertion(
    canonicalJson(observation.blockers) === canonicalJson(KNOWN_BLOCKERS) &&
      canonicalJson(observation.normalizations) === '[]' &&
      observation.authority === 'none' &&
      observation.action === null &&
      observation.outcome.status === 'inconclusive' &&
      observation.outcome.supportEligible === false &&
      observation.outcome.refutationEligible === false,
    'outcome-policy-violation',
    'probe-self-classification'
  );

  const expectedSharedObjects = [...CONTRACT.runtimeFileMounts.slice(1), 'linux-vdso.so.1'].sort(
    bytewise
  );
  assertion(
    canonicalJson(observation.runtime.sharedObjects) === canonicalJson(expectedSharedObjects) &&
      observation.runtime.sharedObjectsSha256 === canonicalHash(expectedSharedObjects),
    'native-closure-drift',
    observation.runtime.sharedObjectsSha256
  );
}

function runProbeAttempt(argv, ordinal) {
  const result = exactSpawn(CONTRACT.launcher.executable, argv);
  assertion(
    result.status === 0 && result.signal === null,
    'probe-execution-failed',
    `${ordinal}:${result.status}:${result.stderr.toString('utf8')}`
  );
  assertion(
    result.stderr.length === 0,
    'probe-stderr-observed',
    `${ordinal}:${sha256(result.stderr)}`
  );
  const stdoutText = result.stdout.toString('utf8');
  assertion(stdoutText.endsWith('\n'), 'probe-serialization-invalid', `${ordinal}:newline`);
  const observation = JSON.parse(stdoutText);
  const canonicalBytes = Buffer.from(`${canonicalJson(observation)}\n`, 'utf8');
  assertion(
    canonicalBytes.equals(result.stdout),
    'probe-serialization-invalid',
    `${ordinal}:${sha256(result.stdout)}`
  );
  validateObservation(observation);
  return {
    observation,
    receipt: {
      exitCode: result.status,
      observationSemanticSha256: canonicalHash(observation),
      ordinal,
      signal: result.signal,
      stderrByteLength: result.stderr.length,
      stderrSha256: sha256(result.stderr),
      stdoutByteLength: result.stdout.length,
      stdoutSha256: sha256(result.stdout),
    },
    stdout: result.stdout,
  };
}

function predicateAssessment() {
  const deferred = new Map([
    ['independentVerifierReconstructs', 'independent-verifier-required'],
    ['allControlsFailClosed', 'independent-hostile-controls-required'],
  ]);
  const blocked = new Map([
    ['selectedNode22Exact', ['path-execution-image-identity-not-atomically-bound']],
    [
      'apparatusSourceClosureExact',
      [
        'successor-apparatus-and-accepted-h054-layer-source-lock-not-established',
        'path-execution-image-identity-not-atomically-bound',
      ],
    ],
    [
      'emptyRootMountClosureExact',
      [
        'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
        'path-execution-image-identity-not-atomically-bound',
      ],
    ],
    [
      'isolatedNetworkNamespaceExact',
      ['bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced'],
    ],
    [
      'failureBranchEvidenceMaterializable',
      ['failed-attempt-evidence-preservation-and-outcome-derivation-not-established'],
    ],
    ['exhaustiveOpenFileAndModuleClosure', ['exhaustive-esm-and-open-file-trace-not-admitted']],
    [
      'effectiveSyscallClosure',
      [
        'content-addressed-effective-seccomp-policy-not-admitted',
        'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
        'worker-and-child-process-cardinality-not-independently-traced',
      ],
    ],
    [
      'nativeAndLateLoadedObjectClosure',
      ['kernel-vdso-and-late-loaded-object-closure-not-established'],
    ],
    [
      'noSuccessorHypothesisOpenedOrExecuted',
      ['universal-successor-absence-not-provable-without-exhaustive-trace'],
    ],
  ]);
  return SUBJECT.requiredPredicates.map((id) => {
    if (deferred.has(id)) return { id, reason: deferred.get(id), status: 'deferred' };
    if (blocked.has(id)) return { blockers: blocked.get(id), id, status: 'blocked' };
    return { id, status: 'passed' };
  });
}

function producerControlReceipts() {
  const ids = SUBJECT.controlContract.map(({ id }) => id);
  assertion(new Set(ids).size === ids.length, 'control-roster-invalid', 'duplicate-id');
  return SUBJECT.controlContract.map(({ expectedReasonCode, id }) => {
    return {
      executionDisposition: 'reject-before-execution',
      expectedReasonCode,
      id,
      launchScope: 'positive-bubblewrap-boundary-only',
      mutationMode: 'in-memory-only',
      observedReasonCode: null,
      passed: null,
      positiveBoundaryLaunchCount: 0,
      status: 'deferred-to-independent-verifier',
    };
  });
}

function semanticBody(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  return body;
}

export async function buildBoundaryEvidence() {
  assertExecutionContract();
  verifyExpectedInputs();
  const anchors = buildAnchors();
  const pre = buildSourceClosure();
  const runtimeSelection = SUBJECT.temporalBoundary.prospectiveRuntimeSelection;
  const nodeBytes = readStableRegularFile(runtimeSelection.commandPath).bytes;
  assertion(
    sha256(nodeBytes) === runtimeSelection.executableSha256,
    'runtime-identity-drift',
    sha256(nodeBytes)
  );
  const bubblewrapBytes = readStableRegularFile(CONTRACT.launcher.executable).bytes;
  const preBubblewrapSha256 = sha256(bubblewrapBytes);
  assertion(
    preBubblewrapSha256 === CONTRACT.launcher.sha256,
    'launcher-identity-drift',
    preBubblewrapSha256
  );
  const versionResult = exactSpawn(CONTRACT.launcher.executable, ['--version']);
  assertion(
    versionResult.status === 0 &&
      versionResult.signal === null &&
      versionResult.stderr.length === 0 &&
      versionResult.stdout.toString('utf8').trim() === CONTRACT.launcher.version,
    'launcher-identity-drift',
    versionResult.stdout.toString('utf8').trim()
  );

  const argv = buildBwrapArgv();
  const attemptResults = [];
  for (let ordinal = 1; ordinal <= CONTRACT.expectedAttemptCount; ordinal += 1) {
    attemptResults.push(runProbeAttempt(argv, ordinal));
  }
  const first = attemptResults[0];
  const byteIdentical = attemptResults.every(({ stdout }) => stdout.equals(first.stdout));
  const semanticIdentical = attemptResults.every(
    ({ receipt }) => receipt.observationSemanticSha256 === first.receipt.observationSemanticSha256
  );
  assertion(byteIdentical && semanticIdentical, 'determinism-failure', 'attempts-diverged');

  const postBubblewrapBytes = readStableRegularFile(CONTRACT.launcher.executable).bytes;
  const postBubblewrapSha256 = sha256(postBubblewrapBytes);
  assertion(
    postBubblewrapSha256 === CONTRACT.launcher.sha256 &&
      postBubblewrapSha256 === preBubblewrapSha256,
    'launcher-identity-drift',
    `${preBubblewrapSha256}:${postBubblewrapSha256}`
  );
  const postVersionResult = exactSpawn(CONTRACT.launcher.executable, ['--version']);
  assertion(
    postVersionResult.status === 0 &&
      postVersionResult.signal === null &&
      postVersionResult.stderr.length === 0 &&
      postVersionResult.stdout.toString('utf8').trim() === CONTRACT.launcher.version,
    'launcher-identity-drift',
    postVersionResult.stdout.toString('utf8').trim()
  );

  const post = buildSourceClosure();
  assertion(
    pre.rootSha256 === post.rootSha256 &&
      canonicalJson(pre.layers) === canonicalJson(post.layers) &&
      canonicalJson(pre.mounts) === canonicalJson(post.mounts),
    'source-closure-stale',
    `${pre.rootSha256}:${post.rootSha256}`
  );
  const postAnchors = buildAnchors();
  assertion(
    canonicalJson(anchors) === canonicalJson(postAnchors),
    'source-closure-stale',
    'anchor-drift'
  );

  const sourceClosure = {
    layers: pre.layers,
    mounts: pre.mounts,
    postRootSha256: post.rootSha256,
    preRootSha256: pre.rootSha256,
    rootSha256: pre.rootSha256,
    stable: true,
  };
  const run = {
    action: null,
    anchors,
    attempts: attemptResults.map(({ receipt }) => receipt),
    authority: 'none',
    blockers: [...KNOWN_BLOCKERS],
    controls: producerControlReceipts(),
    humanReview: {
      accepted: null,
      required: true,
    },
    interpretation: {
      adrCandidate: null,
      claimBoundary:
        'synthetic Node 22 TypeScript, Ajv, and esbuild execution inside the nominated finite offline read-only mount boundary only',
      successorState: {
        observation: 'not-observed-within-nominated-boundary',
        syscallTrace: null,
        universalAbsenceProved: false,
      },
    },
    launcher: {
      bubblewrap: {
        argv,
        argvSha256: canonicalHash(argv),
        executablePath: CONTRACT.launcher.executable,
        executableSha256: preBubblewrapSha256,
        identityWindow: {
          postSha256: postBubblewrapSha256,
          preSha256: preBubblewrapSha256,
          stable: true,
        },
        version: CONTRACT.launcher.version,
      },
      effectiveEnvironment: { ...EXPECTED_ENVIRONMENT },
      mountRosterSha256: canonicalHash(pre.mounts),
      nodeArgv: [...NODE_ARGV],
      nodeArgvSha256: canonicalHash(NODE_ARGV),
    },
    normalizations: [],
    observation: first.observation,
    outcome: {
      reason: 'known-boundary-completeness-blockers-remain',
      refutationEligible: false,
      status: 'inconclusive',
      supportEligible: false,
    },
    predicates: predicateAssessment(),
    repeatability: {
      attemptCount: attemptResults.length,
      byteIdentical,
      observationSemanticSha256: first.receipt.observationSemanticSha256,
      semanticIdentical,
    },
    schemaVersion: SCHEMA_VERSION,
    sourceClosure,
    studyId: SUBJECT.id,
  };
  const semanticSha256 = canonicalHash(run);
  return {
    ...run,
    runId: `node22-boundary-preflight-${semanticSha256.slice(0, 24)}`,
    semanticSha256,
  };
}

export function validateBoundaryEvidenceIdentity(run) {
  const expected = canonicalHash(semanticBody(run));
  assertion(
    run.semanticSha256 === expected &&
      run.runId === `node22-boundary-preflight-${expected.slice(0, 24)}`,
    'evidence-integrity-drift',
    expected
  );
  return expected;
}

export function encodeBoundaryEvidence(run) {
  validateBoundaryEvidenceIdentity(run);
  return Buffer.from(canonicalPrettyJson(run), 'utf8');
}

function boundaryEvidencePaths() {
  const repositoryRoot = REPOSITORY_ROOT;
  const artifactsRoot = path.join(repositoryRoot, 'artifacts');
  const studyRoot = path.join(artifactsRoot, 'node22-boundary-preflight');
  return {
    artifactsRoot,
    repositoryRoot,
    runsRoot: path.join(studyRoot, 'runs'),
    studyRoot,
  };
}

const BOUNDARY_EVIDENCE_PATHS = Object.freeze(boundaryEvidencePaths());

function containedRelative(parent, target) {
  const relative = path.relative(path.resolve(parent), path.resolve(target));
  assertion(
    relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    'raw-path-invalid',
    target
  );
  return relative;
}

function verifyRawEvidencePolicy(repositoryRoot) {
  assertion(
    canonicalJson(SUBJECT.rawEvidencePolicy) === canonicalJson(LOCKED_RAW_EVIDENCE_POLICY),
    'raw-evidence-policy-drift',
    'subject-policy'
  );
  const policy = LOCKED_RAW_EVIDENCE_POLICY;
  const gitignorePath = path.resolve(repositoryRoot, policy.gitignore.locator);
  assertion(
    path.relative(repositoryRoot, gitignorePath) === policy.gitignore.locator,
    'raw-evidence-policy-drift',
    'gitignore-locator'
  );
  const gitignoreBytes = readStableRegularFile(gitignorePath).bytes;
  const rawSha256 = sha256(gitignoreBytes);
  const patternCount = gitignoreBytes
    .toString('utf8')
    .split('\n')
    .filter((line) => line === policy.gitignore.requiredPattern).length;
  assertion(
    rawSha256 === policy.gitignore.rawSha256 &&
      patternCount === 1 &&
      policy.evidenceRootLocator === policy.gitignore.requiredPattern &&
      policy.mustRemainIgnored === true,
    'raw-evidence-policy-drift',
    `${rawSha256}:${patternCount}`
  );
  return {
    evidenceRootLocator: policy.evidenceRootLocator,
    gitignore: { ...policy.gitignore },
    satisfied: true,
  };
}

function assertSafeDirectory(directory, expectedMode, containmentRoot = null) {
  const metadata = lstatSync(directory);
  assertion(metadata.isDirectory() && !metadata.isSymbolicLink(), 'raw-path-invalid', directory);
  assertion(
    expectedMode === null || (metadata.mode & 0o777) === expectedMode,
    'raw-mode-invalid',
    directory
  );
  assertion(metadata.uid === process.getuid(), 'raw-owner-invalid', directory);
  if (containmentRoot !== null) {
    const realRoot = realpathSync(containmentRoot);
    const realDirectory = realpathSync(directory);
    if (realRoot !== realDirectory) containedRelative(realRoot, realDirectory);
  }
  return metadata;
}

function assertNoSymlinkComponents(root, target) {
  const absoluteRoot = realpathSync(root);
  const relative = containedRelative(absoluteRoot, path.resolve(target));
  let current = absoluteRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    const metadata = lstatSync(current);
    assertion(!metadata.isSymbolicLink(), 'raw-path-invalid', current);
  }
}

function createOrInspectPrivateDirectory(directory, containmentRoot) {
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  assertSafeDirectory(directory, 0o700, containmentRoot);
  assertNoSymlinkComponents(containmentRoot, directory);
}

function writeExclusiveRawFile(filePath, bytes, evidenceRoot) {
  const descriptor = openSync(
    filePath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600
  );
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    const metadata = fstatSync(descriptor);
    assertion(
      metadata.isFile() &&
        metadata.nlink === 1 &&
        (metadata.mode & 0o777) === 0o600 &&
        metadata.uid === process.getuid(),
      'raw-file-invalid',
      filePath
    );
  } finally {
    closeSync(descriptor);
  }
  assertNoSymlinkComponents(evidenceRoot, filePath);
  const readDescriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(readDescriptor);
    const observed = readFileSync(readDescriptor);
    assertion(
      metadata.isFile() &&
        metadata.nlink === 1 &&
        (metadata.mode & 0o777) === 0o600 &&
        metadata.uid === process.getuid() &&
        observed.equals(bytes),
      'raw-file-invalid',
      filePath
    );
  } finally {
    closeSync(readDescriptor);
  }
}

export function preserveBoundaryEvidence(run) {
  assertion(arguments.length === 1, 'unexpected-arguments', 'preserve-boundary-evidence');
  const evidencePaths = BOUNDARY_EVIDENCE_PATHS;
  const repositoryRoot = realpathSync(REPOSITORY_ROOT);
  const rawEvidencePolicy = verifyRawEvidencePolicy(repositoryRoot);
  const expectedPaths = {
    artifactsRoot: path.join(repositoryRoot, 'artifacts'),
    repositoryRoot,
    runsRoot: path.join(repositoryRoot, 'artifacts/node22-boundary-preflight/runs'),
    studyRoot: path.join(repositoryRoot, 'artifacts/node22-boundary-preflight'),
  };
  assertion(
    canonicalJson(evidencePaths) === canonicalJson(expectedPaths) &&
      rawEvidencePolicy.evidenceRootLocator === 'artifacts/',
    'raw-path-invalid',
    'canonical-evidence-paths'
  );
  const semanticSha256 = validateBoundaryEvidenceIdentity(run);
  const bytes = encodeBoundaryEvidence(run);
  const artifactsRoot = evidencePaths.artifactsRoot;
  assertSafeDirectory(artifactsRoot, null, repositoryRoot);
  assertNoSymlinkComponents(repositoryRoot, artifactsRoot);
  createOrInspectPrivateDirectory(evidencePaths.studyRoot, artifactsRoot);
  createOrInspectPrivateDirectory(evidencePaths.runsRoot, evidencePaths.studyRoot);
  const runDirectory = path.join(evidencePaths.runsRoot, semanticSha256);
  createOrInspectPrivateDirectory(runDirectory, evidencePaths.runsRoot);
  const runPath = path.join(runDirectory, 'run.json');
  containedRelative(runDirectory, runPath);
  const beforeEntries = readdirSync(runDirectory, { encoding: 'utf8' }).sort(bytewise);
  assertion(beforeEntries.length === 0, 'raw-directory-not-empty', canonicalJson(beforeEntries));
  writeExclusiveRawFile(runPath, bytes, evidencePaths.runsRoot);
  const afterEntries = readdirSync(runDirectory, { encoding: 'utf8' }).sort(bytewise);
  assertion(
    canonicalJson(afterEntries) === canonicalJson(['run.json']),
    'raw-directory-invalid',
    canonicalJson(afterEntries)
  );
  return {
    action: null,
    authority: 'none',
    byteLength: bytes.length,
    creation: 'exclusive',
    directoryMode: '0700',
    fileMode: '0600',
    path: path.relative(repositoryRoot, runPath),
    rawEvidencePolicy,
    rawSha256: sha256(bytes),
    runId: run.runId,
    semanticSha256,
  };
}

async function main() {
  const args = process.argv.slice(2);
  assertion(
    args.length === 0 || (args.length === 1 && args[0] === '--write'),
    'unexpected-arguments',
    canonicalJson(args)
  );
  const run = await buildBoundaryEvidence();
  if (args[0] === '--write') {
    process.stdout.write(`${canonicalJson(preserveBoundaryEvidence(run))}\n`);
    return;
  }
  process.stdout.write(encodeBoundaryEvidence(run));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
