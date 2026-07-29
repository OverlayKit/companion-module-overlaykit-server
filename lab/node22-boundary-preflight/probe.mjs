import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';

const SCHEMA_VERSION = 'overlaykit-node22-boundary-preflight-observation/v1';
const FIXED_NAMESPACE = 'node22-boundary-preflight';
const FIXTURE_PATH = '/workspace/lab/node22-boundary-preflight/fixtures/synthetic-probe.ts';
const TSCONFIG_PATH = '/workspace/lab/node22-boundary-preflight/fixtures/tsconfig.json';

const EXPECTED_ENVIRONMENT = Object.freeze({
  ESBUILD_BINARY_PATH: '/workspace/node_modules/@esbuild/linux-x64/bin/esbuild',
  ESBUILD_WORKER_THREADS: '0',
  HOME: '/home/probe',
  LANG: 'C',
  LC_ALL: 'C',
  NODE_DISABLE_COLORS: '1',
  NODE_DISABLE_COMPILE_CACHE: '1',
  NO_COLOR: '1',
  PATH: '/usr/bin',
  PWD: '/workspace',
  TERM: 'dumb',
  TMPDIR: '/tmp',
  TSX_DISABLE_CACHE: '1',
  TSX_TSCONFIG_PATH: TSCONFIG_PATH,
  TZ: 'UTC',
  XDG_CACHE_HOME: '/tmp',
});

const EXPECTED_EXEC_ARGV = Object.freeze([
  '--permission',
  '--allow-fs-read=/workspace',
  '--allow-fs-read=/WORKSPACE',
  '--allow-fs-read=/tmp',
  '--allow-worker',
  '--allow-child-process',
  '--no-addons',
  '--no-warnings',
]);

const KNOWN_BLOCKERS = Object.freeze([
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
]);

const EXPECTED_SHARED_OBJECTS = Object.freeze([
  '/lib64/ld-linux-x86-64.so.2',
  '/lib64/libbrotlicommon.so.1',
  '/lib64/libbrotlidec.so.1',
  '/lib64/libbrotlienc.so.1',
  '/lib64/libc.so.6',
  '/lib64/libcares.so.2',
  '/lib64/libcrypto.so.3',
  '/lib64/libgcc_s.so.1',
  '/lib64/libm.so.6',
  '/lib64/libnode.so.127',
  '/lib64/libsqlite3.so.0',
  '/lib64/libssl.so.3',
  '/lib64/libstdc++.so.6',
  '/lib64/libuv.so.1',
  '/lib64/libz.so.1',
  'linux-vdso.so.1',
]);

function assertion(condition, reasonCode, detail) {
  if (!condition) {
    throw new Error(`NODE22_PREFLIGHT_PROBE_REFUSED:${reasonCode}:${detail}`);
  }
}

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalValue(entry));
  }
  if (value !== null && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort((left, right) =>
      Buffer.from(left).compare(Buffer.from(right))
    )) {
      result[key] = canonicalValue(value[key]);
    }
    return result;
  }
  assertion(
    value === null || ['boolean', 'number', 'string'].includes(typeof value),
    'canonical-value-invalid',
    String(value)
  );
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function exactEnvironment() {
  const observed = Object.fromEntries(
    Object.keys(process.env)
      .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)))
      .map((name) => [name, process.env[name]])
  );
  assertion(
    canonicalJson(observed) === canonicalJson(EXPECTED_ENVIRONMENT),
    'environment-closure-drift',
    canonicalHash(observed)
  );
  return observed;
}

function exactPermissionEnvelope() {
  assertion(process.permission !== undefined, 'permission-envelope-drift', 'api-absent');
  const envelope = {
    addons: process.permission.has('addons'),
    child: process.permission.has('child'),
    fsReadTmp: process.permission.has('fs.read', '/tmp'),
    fsReadUpperWorkspace: process.permission.has('fs.read', '/WORKSPACE'),
    fsReadWorkspace: process.permission.has('fs.read', '/workspace'),
    fsWriteGlobal: process.permission.has('fs.write'),
    worker: process.permission.has('worker'),
  };
  const expected = {
    addons: false,
    child: true,
    fsReadTmp: true,
    fsReadUpperWorkspace: true,
    fsReadWorkspace: true,
    fsWriteGlobal: false,
    worker: true,
  };
  assertion(
    canonicalJson(envelope) === canonicalJson(expected),
    'permission-envelope-drift',
    canonicalHash(envelope)
  );
  return envelope;
}

function exactInvocation() {
  assertion(
    canonicalJson(process.execArgv) === canonicalJson(EXPECTED_EXEC_ARGV),
    'permission-envelope-drift',
    canonicalHash(process.execArgv)
  );
  assertion(process.argv.length === 2, 'invocation-drift', canonicalJson(process.argv));
  assertion(process.argv[0] === '/usr/bin/node-22', 'runtime-path-drift', process.argv[0]);
  assertion(
    process.argv[1] === '/workspace/lab/node22-boundary-preflight/probe.mjs',
    'apparatus-path-drift',
    process.argv[1]
  );
  return {
    execArgv: [...process.execArgv],
    executable: process.argv[0],
    script: process.argv[1],
  };
}

function exactRuntime() {
  const sharedObjects = [...process.report.getReport().sharedObjects].sort((left, right) =>
    Buffer.from(left).compare(Buffer.from(right))
  );
  assertion(
    canonicalJson(sharedObjects) === canonicalJson(EXPECTED_SHARED_OBJECTS),
    'native-closure-drift',
    canonicalHash(sharedObjects)
  );
  const runtime = {
    arch: process.arch,
    execPath: process.execPath,
    modules: process.versions.modules,
    napi: process.versions.napi,
    platform: process.platform,
    sharedObjects,
    sharedObjectsSha256: canonicalHash(sharedObjects),
    version: process.version,
  };
  const identity = {
    arch: runtime.arch,
    execPath: runtime.execPath,
    modules: runtime.modules,
    napi: runtime.napi,
    platform: runtime.platform,
    version: runtime.version,
  };
  const expectedIdentity = {
    arch: 'x64',
    execPath: '/usr/bin/node-22',
    modules: '127',
    napi: '10',
    platform: 'linux',
    version: 'v22.22.2',
  };
  assertion(
    canonicalJson(identity) === canonicalJson(expectedIdentity),
    'runtime-identity-drift',
    canonicalHash(identity)
  );
  return runtime;
}

function exactScratchState() {
  const entries = readdirSync('/tmp', { encoding: 'utf8' }).sort((left, right) =>
    Buffer.from(left).compare(Buffer.from(right))
  );
  assertion(entries.length === 0, 'mutable-state-observed', canonicalJson(entries));
  return entries;
}

function observeTsconfig(tsconfigBytes) {
  let document;
  try {
    document = JSON.parse(tsconfigBytes.toString('utf8'));
  } catch {
    assertion(false, 'loader-config-escape', sha256(tsconfigBytes));
  }
  assertion(
    document !== null && typeof document === 'object' && !Array.isArray(document),
    'loader-config-escape',
    sha256(tsconfigBytes)
  );
  const extendsValue = Object.hasOwn(document, 'extends') ? document.extends : null;
  assertion(
    extendsValue === null,
    'loader-config-escape',
    canonicalHash({ extends: extendsValue })
  );
  return {
    byteLength: tsconfigBytes.length,
    extends: extendsValue,
    path: TSCONFIG_PATH,
    sha256: sha256(tsconfigBytes),
  };
}

async function observeTsx() {
  const imports = [];
  const { register } = await import('tsx/esm/api');
  assertion(typeof register === 'function', 'module-universe-incomplete', 'tsx-register-absent');
  const registration = register({
    namespace: FIXED_NAMESPACE,
    onImport(url) {
      imports.push(url);
    },
    tsconfig: TSCONFIG_PATH,
  });
  try {
    const fixture = await registration.import(FIXTURE_PATH, import.meta.url);
    assertion(fixture.syntheticNonNormative === true, 'synthetic-tsx-observation-failed', 'marker');
    assertion(fixture.syntheticAnswer(19, 23) === 42, 'synthetic-tsx-observation-failed', 'answer');
  } finally {
    await registration.unregister();
  }
  const expectedFixtureUrl =
    'file:///workspace/lab/node22-boundary-preflight/fixtures/synthetic-probe.ts';
  const importUrls = [...new Set(imports)].sort((left, right) =>
    Buffer.from(left).compare(Buffer.from(right))
  );
  assertion(
    canonicalJson(importUrls) === canonicalJson([expectedFixtureUrl]),
    'synthetic-tsx-observation-failed',
    canonicalHash(importUrls)
  );
  return {
    answer: 42,
    configMode: 'explicit-register-option',
    importUrls,
    namespace: FIXED_NAMESPACE,
    scopedRegistration: true,
    syntheticNonNormative: true,
  };
}

async function observeAjv() {
  const { default: Ajv } = await import('ajv');
  const ajv = new Ajv({ allErrors: true, strict: true });
  const validate = ajv.compile({
    additionalProperties: false,
    properties: {
      answer: { const: 42, type: 'integer' },
      synthetic: { const: true, type: 'boolean' },
    },
    required: ['answer', 'synthetic'],
    type: 'object',
  });
  const validInput = { answer: 42, synthetic: true };
  const invalidInput = { answer: 41, synthetic: true };
  const validAccepted = validate(validInput) === true;
  const invalidAccepted = validate(invalidInput) === true;
  const invalidKeywords = (validate.errors ?? [])
    .map(({ keyword }) => keyword)
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  assertion(validAccepted, 'synthetic-ajv-observation-failed', 'valid-rejected');
  assertion(!invalidAccepted, 'synthetic-ajv-observation-failed', 'invalid-accepted');
  assertion(
    canonicalJson(invalidKeywords) === canonicalJson(['const']),
    'synthetic-ajv-observation-failed',
    canonicalJson(invalidKeywords)
  );
  return {
    invalidAccepted,
    invalidInput,
    invalidKeywords,
    validAccepted,
    validInput,
  };
}

async function observeEsbuild(sourceBytes) {
  const esbuild = await import('esbuild');
  const options = {
    charset: 'utf8',
    format: 'esm',
    legalComments: 'none',
    loader: 'ts',
    minify: false,
    sourcemap: false,
    target: 'es2022',
    treeShaking: true,
  };
  const transformed = await esbuild.transform(sourceBytes.toString('utf8'), options);
  esbuild.stop();
  assertion(
    transformed.code.includes('syntheticAnswer'),
    'synthetic-esbuild-observation-failed',
    sha256(Buffer.from(transformed.code, 'utf8'))
  );
  assertion(transformed.warnings.length === 0, 'synthetic-esbuild-observation-failed', 'warnings');
  const observation = {
    codeByteLength: Buffer.byteLength(transformed.code, 'utf8'),
    codeSha256: sha256(Buffer.from(transformed.code, 'utf8')),
    input: FIXTURE_PATH,
    options,
    warningCount: transformed.warnings.length,
  };
  assertion(
    canonicalJson(observation) ===
      canonicalJson({
        codeByteLength: 156,
        codeSha256: '4c00f4280b91ec851a19f0f046b4f05cafcc107399f03de18c4f6a9c8e30b197',
        input: FIXTURE_PATH,
        options,
        warningCount: 0,
      }),
    'synthetic-esbuild-observation-failed',
    canonicalHash(observation)
  );
  return observation;
}

async function main() {
  const environment = exactEnvironment();
  const invocation = exactInvocation();
  const permissionEnvelope = exactPermissionEnvelope();
  let caseVariantErrorCode = null;
  try {
    lstatSync('/WORKSPACE');
  } catch (error) {
    caseVariantErrorCode = error?.code ?? null;
  }
  const caseVariantAbsent = caseVariantErrorCode === 'ENOENT';
  assertion(
    caseVariantAbsent,
    'loader-config-escape',
    caseVariantErrorCode ?? '/WORKSPACE-present'
  );
  const scratchBefore = exactScratchState();
  const fixtureBytes = readFileSync(FIXTURE_PATH);
  const tsconfigBytes = readFileSync(TSCONFIG_PATH);
  const tsconfig = observeTsconfig(tsconfigBytes);
  const tsx = await observeTsx();
  const ajv = await observeAjv();
  const esbuild = await observeEsbuild(fixtureBytes);
  const scratchAfter = exactScratchState();
  const runtime = exactRuntime();

  const observation = {
    action: null,
    ajv,
    authority: 'none',
    blockers: [...KNOWN_BLOCKERS],
    environment,
    esbuild,
    fixture: {
      byteLength: fixtureBytes.length,
      path: FIXTURE_PATH,
      sha256: sha256(fixtureBytes),
    },
    invocation,
    normalizations: [],
    outcome: {
      reason: 'known-boundary-completeness-blockers-remain',
      refutationEligible: false,
      status: 'inconclusive',
      supportEligible: false,
    },
    permissionEnvelope,
    pathResolution: {
      caseVariantAbsent,
      caseVariantErrorCode,
      caseVariantPath: '/WORKSPACE',
    },
    runtime,
    schemaVersion: SCHEMA_VERSION,
    scratch: {
      after: scratchAfter,
      before: scratchBefore,
    },
    tsconfig,
    tsx,
  };
  process.stdout.write(`${canonicalJson(observation)}\n`);
}

await main();
