import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import test from 'node:test';
import {
  H044_EVIDENCE_SHA256,
  H044_PUBLIC_RECEIPT_PATH,
  H044_PUBLIC_RECEIPT_RELATIVE_PATH,
  H044_PUBLIC_RECEIPT_SHA256,
  H045_ACCEPTED_IMAGE_ID,
  H045_ACCEPTED_IMAGE_REFERENCE,
  H045_ACCEPTED_PRODUCT_ID,
  H045_ACCEPTED_SERIAL_BINDING,
  H045_ACCEPTED_VENDOR_ID,
  H045_ADR_0006_SHA256,
  H045_CHG_0018_SHA256,
  H045_CHG_0019_SHA256,
  H045_CHG_0020_SHA256,
  H045_GOVERNANCE_MANIFEST_SHA256,
  H045_GOVERNANCE_PLAN_SHA256,
  H045_MANIFEST_CONTENT_HASH,
  H045_NODE_ARCH,
  H045_NODE_BINARY_BYTE_LENGTH,
  H045_NODE_BINARY_SHA256,
  H045_NODE_PLATFORM,
  H045_NODE_VERSION,
  H045_PLAN_HASH,
  H045_PROTECTED_MAIN_COMMIT,
  H045_REPOSITORY,
  H045_REQUIRED_SOURCE_PATHS,
  H045_SOURCE_CONTRACT_COMMIT,
  H045_STABLE_TARGET_INPUT,
  buildSourceAdmission,
  readHistoricalEvidence,
  sourceMapExact,
  sourceSetSha256,
  stableTargetInputExact,
} from './admission-lib.mjs';

const ADR_0006_URL = new URL(
  '../../.overlaykit/governance/decisions/ADR-0006.json',
  import.meta.url
);
const GOVERNANCE_MANIFEST_URL = new URL(
  '../../.overlaykit/governance/manifest.json',
  import.meta.url
);
const CHG_0018_URL = new URL('../../.overlaykit/governance/changes/CHG-0018.json', import.meta.url);
const CHG_0019_URL = new URL('../../.overlaykit/governance/changes/CHG-0019.json', import.meta.url);
const CHG_0020_URL = new URL('../../.overlaykit/governance/changes/CHG-0020.json', import.meta.url);
const MODULE_URL = new URL('./admission-lib.mjs', import.meta.url);

const GOVERNANCE = Object.freeze({
  verified: true,
  planHash: H045_PLAN_HASH,
  planSha256: H045_GOVERNANCE_PLAN_SHA256,
  manifestContentHash: H045_MANIFEST_CONTENT_HASH,
  manifestSha256: H045_GOVERNANCE_MANIFEST_SHA256,
  changes: Object.freeze({
    'CHG-0018': H045_CHG_0018_SHA256,
    'CHG-0019': H045_CHG_0019_SHA256,
    'CHG-0020': H045_CHG_0020_SHA256,
  }),
  decisions: Object.freeze({
    'ADR-0006': H045_ADR_0006_SHA256,
  }),
  requiredSourcePaths: H045_REQUIRED_SOURCE_PATHS,
});

const GIT = Object.freeze({
  repositoryRemote: H045_REPOSITORY,
  head: H045_SOURCE_CONTRACT_COMMIT,
  protectedMainCommit: H045_PROTECTED_MAIN_COMMIT,
  sourceContractCommit: H045_SOURCE_CONTRACT_COMMIT,
  protectedMainAncestor: true,
  sourceContractAncestor: true,
});

const RUNTIME = Object.freeze({
  node: H045_NODE_VERSION,
  platform: H045_NODE_PLATFORM,
  arch: H045_NODE_ARCH,
  binarySha256: H045_NODE_BINARY_SHA256,
  binaryByteLength: H045_NODE_BINARY_BYTE_LENGTH,
});

function clone(value) {
  return structuredClone(value);
}

function sourceMap(suffix = '') {
  return H045_REQUIRED_SOURCE_PATHS.map((path) => ({
    path,
    sha256: createHash('sha256').update(`${path}${suffix}`).digest('hex'),
  }));
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

async function historicalEvidence() {
  const [receipt, decision] = await Promise.all([
    readFile(H044_PUBLIC_RECEIPT_PATH),
    readFile(ADR_0006_URL),
  ]);
  return readHistoricalEvidence(receipt, decision);
}

function exactInput(historical, sources = sourceMap()) {
  return {
    historical: clone(historical),
    governance: clone(GOVERNANCE),
    git: clone(GIT),
    runtime: clone(RUNTIME),
    targetInput: clone(H045_STABLE_TARGET_INPUT),
    sourcesBefore: clone(sources),
    sourcesAfter: clone(sources),
  };
}

test('binds the executing Node binary by content rather than its temporary path', async () => {
  const [binary, binarySha256] = await Promise.all([
    stat(process.execPath),
    sha256File(process.execPath),
  ]);
  assert.deepEqual(
    {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      binarySha256,
      binaryByteLength: binary.size,
    },
    RUNTIME
  );
});

test('binds the exact CHG-0018 through CHG-0020 and successor manifest bytes', async () => {
  const [manifestBytes, manifestSha256, chg0018Sha256, chg0019Sha256, chg0020Sha256] =
    await Promise.all([
      readFile(GOVERNANCE_MANIFEST_URL),
      sha256File(GOVERNANCE_MANIFEST_URL),
      sha256File(CHG_0018_URL),
      sha256File(CHG_0019_URL),
      sha256File(CHG_0020_URL),
    ]);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));

  assert.equal(manifestSha256, H045_GOVERNANCE_MANIFEST_SHA256);
  assert.equal(manifest.contentHash, H045_MANIFEST_CONTENT_HASH);
  assert.deepEqual(
    {
      'CHG-0018': chg0018Sha256,
      'CHG-0019': chg0019Sha256,
      'CHG-0020': chg0020Sha256,
    },
    {
      'CHG-0018': H045_CHG_0018_SHA256,
      'CHG-0019': H045_CHG_0019_SHA256,
      'CHG-0020': H045_CHG_0020_SHA256,
    }
  );
  assert.deepEqual(
    {
      'CHG-0018': manifest.changes['CHG-0018'],
      'CHG-0019': manifest.changes['CHG-0019'],
      'CHG-0020': manifest.changes['CHG-0020'],
    },
    GOVERNANCE.changes
  );
});

test('freezes a sorted complete source set without private H-044 raw artifacts', () => {
  assert.deepEqual(H045_REQUIRED_SOURCE_PATHS, [...H045_REQUIRED_SOURCE_PATHS].sort());
  assert.equal(H045_REQUIRED_SOURCE_PATHS.length, 24);
  assert.deepEqual(
    H045_REQUIRED_SOURCE_PATHS.filter((path) => path.startsWith('lab/h045/')),
    [
      'lab/h045/admission-lib.mjs',
      'lab/h045/admission-lib.test.mjs',
      'lab/h045/classifier-lib.mjs',
      'lab/h045/classifier-lib.test.mjs',
      'lab/h045/observer-lib.mjs',
      'lab/h045/observer-lib.test.mjs',
      'lab/h045/run.mjs',
      'lab/h045/run.test.mjs',
      'lab/h045/schema.test.mjs',
      'lab/h045/schemas/live-run.schema.json',
      'lab/h045/verify.mjs',
      'lab/h045/verify.test.mjs',
    ].sort()
  );
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes('lab/h041/host-inventory.mjs'), true);
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes('lab/h044/observer-lib.mjs'), true);
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes('lab/h046/environment-seam.test.mjs'), true);
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes(H044_PUBLIC_RECEIPT_RELATIVE_PATH), true);
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/plan.json'), true);
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/manifest.json'), true);
  assert.equal(
    H045_REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0020.json'),
    true
  );
  assert.equal(
    H045_REQUIRED_SOURCE_PATHS.some(
      (path) => path.includes('artifacts/h044') || path.includes('replay-')
    ),
    false
  );
});

test('admits only the public H-044 receipt and reconstructs the target from exact ADR-0006', async () => {
  const historical = await historicalEvidence();
  const moduleSource = await readFile(MODULE_URL, 'utf8');

  assert.equal(historical.exact, true);
  assert.deepEqual(historical.publicReceipt, {
    path: H044_PUBLIC_RECEIPT_RELATIVE_PATH,
    sha256: H044_PUBLIC_RECEIPT_SHA256,
    byteLength: 2_359,
  });
  assert.deepEqual(historical.canonical, {
    runId: 'h044-2026-07-27T02-46-55-692Z-799230e4',
    outcome: 'supported',
    liveDisposition: 'withheld',
    stage: 'not-eligible',
    reasonCode: 'historical-container-absent',
    candidateReceipts: 0,
    semanticEvidenceSha256: H044_EVIDENCE_SHA256,
  });
  assert.deepEqual(historical.decisionReceipt, {
    id: 'ADR-0006',
    status: 'accepted',
    sha256: H045_ADR_0006_SHA256,
    serialSha256: H045_ACCEPTED_SERIAL_BINDING.serialSha256,
  });
  assert.equal(historical.acceptedTarget.imageReference, H045_ACCEPTED_IMAGE_REFERENCE);
  assert.equal(historical.acceptedTarget.imageId, H045_ACCEPTED_IMAGE_ID);
  assert.equal(historical.acceptedTarget.vendorId, H045_ACCEPTED_VENDOR_ID);
  assert.equal(historical.acceptedTarget.productId, H045_ACCEPTED_PRODUCT_ID);
  assert.match(historical.acceptedTarget.serial, /^[A-Z][A-Z0-9]{13}$/u);
  assert.equal(
    moduleSource.includes(historical.acceptedTarget.serial),
    false,
    'the accepted serial must be reconstructed from ADR-0006, not embedded in source'
  );
  assert.deepEqual(historical.boundary, {
    rawH044ArtifactsRequired: false,
    authority: 'none',
    action: null,
  });
});

test('rejects byte drift and non-byte historical inputs before semantic admission', async () => {
  const [receipt, decision] = await Promise.all([
    readFile(H044_PUBLIC_RECEIPT_PATH),
    readFile(ADR_0006_URL),
  ]);
  const receiptTampered = Buffer.from(receipt);
  receiptTampered[receiptTampered.length - 1] ^= 0x01;
  const decisionTampered = Buffer.from(decision);
  decisionTampered[decisionTampered.length - 1] ^= 0x01;

  assert.throws(
    () => readHistoricalEvidence(receiptTampered, decision),
    /public H-044 receipt SHA-256/u
  );
  assert.throws(() => readHistoricalEvidence(receipt, decisionTampered), /ADR-0006 SHA-256/u);
  assert.throws(() => readHistoricalEvidence('receipt', decision), /publicReceiptBytes/u);
  assert.throws(() => readHistoricalEvidence(receipt, 'decision'), /adr0006Bytes/u);
});

test('admits only stable target selectors and their exact accepted serial binding', () => {
  assert.equal(stableTargetInputExact(clone(H045_STABLE_TARGET_INPUT)), true);

  const volatileKeys = [
    'containerId',
    'pid1',
    'workerPid',
    'startTicks',
    'pidNamespace',
    'mountNamespace',
    'cgroup',
    'descriptor',
    'devicePath',
    'inode',
    'rdev',
  ];
  for (const key of volatileKeys) {
    const input = clone(H045_STABLE_TARGET_INPUT);
    input[key] = 'historical-value';
    assert.equal(stableTargetInputExact(input), false, key);
  }

  const nestedVolatile = clone(H045_STABLE_TARGET_INPUT);
  nestedVolatile.serialBinding.workerPid = 73;
  assert.equal(stableTargetInputExact(nestedVolatile), false);

  const cyclic = clone(H045_STABLE_TARGET_INPUT);
  cyclic.serialBinding.cycle = cyclic;
  assert.equal(stableTargetInputExact(cyclic), false);

  for (const [key, value] of [
    ['imageReference', 'ghcr.io/bitfocus/companion/companion:latest'],
    ['imageId', `sha256:${'0'.repeat(64)}`],
    ['vendorId', '0000'],
    ['productId', '0000'],
  ]) {
    const input = clone(H045_STABLE_TARGET_INPUT);
    input[key] = value;
    assert.equal(stableTargetInputExact(input), false, key);
  }

  const wrongBinding = clone(H045_STABLE_TARGET_INPUT);
  wrongBinding.serialBinding.serialSha256 = '0'.repeat(64);
  assert.equal(stableTargetInputExact(wrongBinding), false);
});

test('builds an exact fail-closed admission and releases only the ADR-derived target', async () => {
  const historical = await historicalEvidence();
  const input = exactInput(historical);
  const admission = buildSourceAdmission(input);

  assert.deepEqual(admission, {
    historicalExact: true,
    governanceExact: true,
    gitExact: true,
    runtimeExact: true,
    targetInputExact: true,
    sourceSetExact: true,
    sourceStable: true,
    exact: true,
    acceptedTarget: historical.acceptedTarget,
    checks: {
      h044PublicReceiptExact: true,
      h044SemanticEvidenceExact: true,
      acceptedDecisionExact: true,
      acceptedTargetContextExact: true,
      historicalBoundaryExact: true,
      governanceVerified: true,
      governancePlanExact: true,
      governancePlanBytesExact: true,
      governanceManifestExact: true,
      governanceManifestBytesExact: true,
      governanceChangesExact: true,
      chg0020Exact: true,
      governanceDecisionExact: true,
      governanceSourcePathsExact: true,
      repositoryRemoteExact: true,
      observedHeadWellFormed: true,
      protectedMainExact: true,
      sourceContractExact: true,
      protectedMainAncestor: true,
      sourceContractAncestor: true,
      nodeRuntimeExact: true,
      stableTargetInputExact: true,
      sourcesBeforeExact: true,
      sourcesAfterExact: true,
    },
  });
  assert.notEqual(admission.acceptedTarget, input.historical.acceptedTarget);
  admission.acceptedTarget.serial = 'mutated';
  assert.notEqual(input.historical.acceptedTarget.serial, 'mutated');
});

test('canonically binds the complete ordered source map and rejects shape drift', () => {
  const sources = sourceMap();
  const differentlyOrderedKeys = sources.map((entry) => ({
    sha256: entry.sha256,
    path: entry.path,
  }));
  assert.equal(sourceMapExact(sources), true);
  assert.equal(sourceSetSha256(sources), sourceSetSha256(differentlyOrderedKeys));
  assert.match(sourceSetSha256(sources), /^[0-9a-f]{64}$/u);

  const reordered = clone(sources).reverse();
  assert.equal(sourceMapExact(reordered), false);
  assert.throws(() => sourceSetSha256(reordered), /exact required source set/u);

  const expanded = clone(sources);
  expanded[0].authority = 'invented';
  assert.equal(sourceMapExact(expanded), false);
  assert.throws(() => sourceSetSha256(expanded), /exact required source set/u);
});

test('admits a well-formed source-anchor descendant without treating its path or SHA as authority', async () => {
  const historical = await historicalEvidence();
  const input = exactInput(historical);
  input.git.head = 'f'.repeat(40);

  const admission = buildSourceAdmission(input);
  assert.equal(admission.checks.observedHeadWellFormed, true);
  assert.equal(admission.gitExact, true);
  assert.equal(admission.exact, true);
});

test('returns explicit false booleans and no target for missing inputs', () => {
  const admission = buildSourceAdmission();
  assert.equal(admission.exact, false);
  assert.equal(admission.historicalExact, false);
  assert.equal(admission.governanceExact, false);
  assert.equal(admission.gitExact, false);
  assert.equal(admission.runtimeExact, false);
  assert.equal(admission.targetInputExact, false);
  assert.equal(admission.sourceSetExact, false);
  assert.equal(admission.sourceStable, false);
  assert.equal(admission.acceptedTarget, null);
  assert.equal(
    Object.values(admission.checks).every((value) => typeof value === 'boolean'),
    true
  );
});

test('withholds the accepted target for every admission-boundary drift', async () => {
  const historical = await historicalEvidence();
  const cases = [
    {
      id: 'public-receipt',
      mutate(input) {
        input.historical.publicReceipt.sha256 = '0'.repeat(64);
      },
      field: 'historicalExact',
    },
    {
      id: 'semantic-evidence',
      mutate(input) {
        input.historical.canonical.semanticEvidenceSha256 = '0'.repeat(64);
      },
      field: 'historicalExact',
    },
    {
      id: 'accepted-serial',
      mutate(input) {
        input.historical.acceptedTarget.serial = 'A0000000000000';
      },
      field: 'historicalExact',
    },
    {
      id: 'accepted-serial-type',
      mutate(input) {
        input.historical.acceptedTarget.serial = 42;
      },
      field: 'historicalExact',
    },
    {
      id: 'manifest',
      mutate(input) {
        input.governance.manifestContentHash = '0'.repeat(64);
      },
      field: 'governanceExact',
    },
    {
      id: 'plan-full-bytes',
      mutate(input) {
        input.governance.planSha256 = '0'.repeat(64);
      },
      field: 'governanceExact',
    },
    {
      id: 'manifest-full-bytes',
      mutate(input) {
        input.governance.manifestSha256 = '0'.repeat(64);
      },
      field: 'governanceExact',
    },
    {
      id: 'extra-governance-change',
      mutate(input) {
        input.governance.changes['CHG-9999'] = '0'.repeat(64);
      },
      field: 'governanceExact',
      check: 'governanceChangesExact',
    },
    {
      id: 'chg-0018',
      mutate(input) {
        input.governance.changes['CHG-0018'] = '0'.repeat(64);
      },
      field: 'governanceExact',
      check: 'governanceChangesExact',
    },
    {
      id: 'chg-0019',
      mutate(input) {
        input.governance.changes['CHG-0019'] = '0'.repeat(64);
      },
      field: 'governanceExact',
      check: 'governanceChangesExact',
    },
    {
      id: 'chg-0020',
      mutate(input) {
        input.governance.changes['CHG-0020'] = '0'.repeat(64);
      },
      field: 'governanceExact',
      check: 'chg0020Exact',
    },
    {
      id: 'repository-remote',
      mutate(input) {
        input.git.repositoryRemote = 'https://example.invalid/repository.git';
      },
      field: 'gitExact',
    },
    {
      id: 'malformed-observed-head',
      mutate(input) {
        input.git.head = 'not-a-git-commit';
      },
      field: 'gitExact',
    },
    {
      id: 'protected-main-commit',
      mutate(input) {
        input.git.protectedMainCommit = '0'.repeat(40);
      },
      field: 'gitExact',
    },
    {
      id: 'source-contract-commit',
      mutate(input) {
        input.git.sourceContractCommit = '0'.repeat(40);
      },
      field: 'gitExact',
    },
    {
      id: 'ancestry',
      mutate(input) {
        input.git.protectedMainAncestor = false;
      },
      field: 'gitExact',
    },
    {
      id: 'source-contract-ancestry',
      mutate(input) {
        input.git.sourceContractAncestor = false;
      },
      field: 'gitExact',
    },
    {
      id: 'runtime-node',
      mutate(input) {
        input.runtime.node = 'v22.20.1';
      },
      field: 'runtimeExact',
    },
    {
      id: 'runtime-platform',
      mutate(input) {
        input.runtime.platform = 'darwin';
      },
      field: 'runtimeExact',
    },
    {
      id: 'runtime-arch',
      mutate(input) {
        input.runtime.arch = 'arm64';
      },
      field: 'runtimeExact',
    },
    {
      id: 'runtime-binary-sha256',
      mutate(input) {
        input.runtime.binarySha256 = '0'.repeat(64);
      },
      field: 'runtimeExact',
    },
    {
      id: 'runtime-binary-byte-length',
      mutate(input) {
        input.runtime.binaryByteLength += 1;
      },
      field: 'runtimeExact',
    },
    {
      id: 'target-input',
      mutate(input) {
        input.targetInput.containerId = '0'.repeat(64);
      },
      field: 'targetInputExact',
    },
    {
      id: 'missing-source',
      mutate(input) {
        input.sourcesAfter.pop();
      },
      field: 'sourceSetExact',
    },
    {
      id: 'reordered-source',
      mutate(input) {
        [input.sourcesAfter[0], input.sourcesAfter[1]] = [
          input.sourcesAfter[1],
          input.sourcesAfter[0],
        ];
      },
      field: 'sourceSetExact',
    },
    {
      id: 'duplicate-source',
      mutate(input) {
        input.sourcesAfter[1] = clone(input.sourcesAfter[0]);
      },
      field: 'sourceSetExact',
    },
    {
      id: 'source-hash-drift',
      mutate(input) {
        input.sourcesAfter[0].sha256 = '0'.repeat(64);
      },
      field: 'sourceStable',
    },
    {
      id: 'same-source-array-object',
      mutate(input) {
        input.sourcesAfter = input.sourcesBefore;
      },
      field: 'sourceStable',
    },
  ];

  for (const entry of cases) {
    const input = exactInput(historical);
    entry.mutate(input);
    const admission = buildSourceAdmission(input);
    assert.equal(admission.exact, false, entry.id);
    assert.equal(admission[entry.field], false, `${entry.id}:${entry.field}`);
    if (entry.check !== undefined) {
      assert.equal(admission.checks[entry.check], false, `${entry.id}:${entry.check}`);
    }
    assert.equal(admission.acceptedTarget, null, `${entry.id}:acceptedTarget`);
  }
});
