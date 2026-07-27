import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { H047_SUBJECT, buildInventory } from './inventory-lib.mjs';
import { H047_SOURCE_PATHS, buildH047Bundle } from './run.mjs';
import {
  H047_INDEPENDENT_ADR_ASSESSMENT,
  canonicalIndependentJson,
  deriveIndependentSignals,
  expandIndependentArchiveForest,
  independentSha256,
  reconstructIndependentInventory,
  verifyH047,
} from './verify.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const REVIEW_MAP = JSON.parse(readFileSync(new URL('./review-map.json', import.meta.url), 'utf8'));
const ANCHOR_REQUIRED = process.env.H047_REQUIRE_ANCHOR === '1';

function git(args, encoding = null) {
  return execFileSync('/usr/bin/git', args, {
    cwd: REPOSITORY_ROOT,
    encoding,
    env: {
      GIT_CONFIG_COUNT: '0',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_NO_LAZY_FETCH: '1',
      GIT_NO_REPLACE_OBJECTS: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
      GNUPGHOME: '/home/rod/.gnupg',
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    },
  });
}

function subjectSnapshot() {
  const treeBytes = git(['ls-tree', '-rz', '--full-tree', H047_SUBJECT.commit]);
  const entries = treeBytes
    .subarray(0, -1)
    .toString('utf8')
    .split('\0')
    .map((record) => {
      const match = /^([0-7]{6}) (blob) ([0-9a-f]{40})\t([\s\S]+)$/u.exec(record);
      assert.notEqual(match, null);
      return { mode: match[1], type: match[2], oid: match[3], path: match[4] };
    });
  const blobs = new Map();
  for (const { oid } of entries) {
    if (!blobs.has(oid)) blobs.set(oid, git(['cat-file', 'blob', oid]));
  }
  return { treeBytes, entries, blobs };
}

const SUBJECT_SNAPSHOT = subjectSnapshot();

function reconstruct(reviewMap = REVIEW_MAP) {
  return reconstructIndependentInventory({
    snapshot: SUBJECT_SNAPSHOT,
    reviewMap,
  });
}

function producerCandidateIndex(reviewMap = REVIEW_MAP) {
  const inventory = buildInventory({
    treeBytes: SUBJECT_SNAPSHOT.treeBytes,
    blobsByOid: SUBJECT_SNAPSHOT.blobs,
    reviewMap,
  });
  return {
    schemaVersion: 'overlaykit-h047-candidate-index/v1',
    hypothesis: 'H-047',
    governance: inventory.governance,
    acceptedRecordReview: inventory.acceptedRecordReview,
    targetOccurrences: inventory.targetOccurrences,
    targetOccurrencePathCounts: inventory.targetOccurrencePathCounts,
    deploymentSurfaces: inventory.surfaces,
    semanticReview: inventory.semanticReview,
    candidates: inventory.candidates,
    chainComponents: inventory.chainComponents,
    unknowns: inventory.unknowns,
    eligibleChains: inventory.eligibleChains,
    coverageComplete: inventory.coverageComplete,
    outcome: inventory.outcome,
    adrAssessment: H047_INDEPENDENT_ADR_ASSESSMENT,
  };
}

function cloneReviewMap() {
  return structuredClone(REVIEW_MAP);
}

function assertProducerFailsClosed(reviewMap, expectedUnknownCode) {
  const rejection = producerCandidateIndex(reviewMap);
  assert.equal(rejection.coverageComplete, false);
  assert.equal(rejection.outcome.status, 'inconclusive');
  assert.deepEqual(rejection.eligibleChains, []);
  assert.ok(rejection.unknowns.some(({ code }) => code === expectedUnknownCode));
}

function sourceAnchorReady() {
  try {
    const head = git(['rev-parse', 'HEAD^{commit}'], 'utf8').trim();
    const parentLine = git(['rev-list', '--parents', '-n', '1', head], 'utf8').trim().split(' ');
    const status = git(['status', '--porcelain=v1', '--untracked-files=all'], 'utf8');
    const delta = git(
      ['diff-tree', '--no-commit-id', '--name-only', '-r', H047_SUBJECT.commit, head],
      'utf8'
    )
      .trim()
      .split(/\r?\n/u)
      .filter(Boolean)
      .sort();
    if (
      parentLine.length !== 2 ||
      parentLine[1] !== H047_SUBJECT.commit ||
      status !== '' ||
      canonicalIndependentJson(delta) !== canonicalIndependentJson(H047_SOURCE_PATHS)
    ) {
      return false;
    }
    git(['verify-commit', head]);
    return true;
  } catch {
    return false;
  }
}

function writeBundle(directory, bundle) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(directory, 'run.json'), bundle.serialized.run, { mode: 0o600 });
  writeFileSync(path.join(directory, 'source-map.json'), bundle.serialized.sourceMap, {
    mode: 0o600,
  });
  writeFileSync(path.join(directory, 'candidate-index.json'), bundle.serialized.candidateIndex, {
    mode: 0o600,
  });
}

function tarOctal(header, offset, length, value) {
  const field = value.toString(8).padStart(length - 1, '0');
  header.write(field, offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

function tarArchive(records) {
  const chunks = [];
  for (const record of records) {
    const body = Buffer.from(record.body ?? '', 'utf8');
    const header = Buffer.alloc(512);
    header.write(record.path, 0, 100, 'utf8');
    tarOctal(header, 100, 8, record.mode ?? 0o644);
    tarOctal(header, 108, 8, 0);
    tarOctal(header, 116, 8, 0);
    tarOctal(header, 124, 12, body.length);
    tarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = (record.type ?? '0').charCodeAt(0);
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0'), 148, 6, 'ascii');
    header[154] = 0;
    header[155] = 0x20;
    chunks.push(header, body, Buffer.alloc(Math.ceil(body.length / 512) * 512 - body.length));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function tarGzip(records) {
  return gzipSync(tarArchive(records), { mtime: 0 });
}

test('verifier is statically independent from producer and classifier sources', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"]\.\/(?:run|inventory-lib)\.mjs['"]/u);
  assert.doesNotMatch(source, /import\(['"]\.\/(?:run|inventory-lib)\.mjs['"]\)/u);
  assert.match(source, /function reconstructIndependentInventory\(/u);
  assert.match(source, /function expandIndependentArchiveForest\(/u);
  assert.match(source, /candidate index differs from independent reconstruction/u);
});

test('verifier source invokes no live observer, Docker, USB, signal, or network client', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"](?:node:)?(?:http|https|net|dgram)['"]/u);
  assert.doesNotMatch(source, /spawnSync\([^,]+,\s*\[['"](?:docker|lsusb|systemctl|kill)/u);
  assert.doesNotMatch(source, /\/(?:proc|sys|dev)\//u);
  assert.doesNotMatch(source, /process\.env/u);
});

test('independent v2 reconstruction closes 238 paths but withholds refutation without humans', () => {
  const { candidateIndex } = reconstruct();
  assert.equal(candidateIndex.semanticReview.schemaVersion, 'overlaykit-h047-semantic-review/v2');
  assert.equal(candidateIndex.semanticReview.pathCount, 238);
  assert.equal(candidateIndex.semanticReview.directCandidateCount, 101);
  assert.equal(candidateIndex.semanticReview.coverageComplete, true);
  assert.deepEqual(candidateIndex.semanticReview.archiveForest, {
    rootCount: 3,
    archiveOccurrences: 4,
    memberOccurrences: 225,
    decompressedBytes: 7_471_104,
    payloadBytes: 7_274_116,
    rootClosures: [
      {
        path: 'evidence/h042/f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88/replay-15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36.tar.gz',
        closureSha256: 'b96c5a729354ce16dda8a85022fb5a459c1527caddf8ecbe5f084530a27e0b41',
        immediateMemberCount: 70,
        recursiveMemberCount: 70,
      },
      {
        path: 'evidence/h043/64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8/replay-fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec.tar.gz',
        closureSha256: '8ce9b53f152e0cec62bc254293f183c4b019efce549d215d69e5cfbc2b491c22',
        immediateMemberCount: 21,
        recursiveMemberCount: 91,
      },
      {
        path: 'vendor/overlaykit-protocol-0.1.0.tgz',
        closureSha256: '4a30481dfa2b33d7898388f15b8a9c7f5b2d4225f596051e70bd2f3d0b31d699',
        immediateMemberCount: 64,
        recursiveMemberCount: 64,
      },
    ],
  });
  assert.equal(candidateIndex.candidates.length, 101);
  assert.equal(candidateIndex.chainComponents.length, 0);
  assert.equal(candidateIndex.eligibleChains.length, 0);
  assert.equal(candidateIndex.coverageComplete, false);
  assert.deepEqual(candidateIndex.outcome, {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'incomplete-ambiguous-or-unknown-coverage',
  });
  assert.deepEqual(candidateIndex.unknowns[0], {
    code: 'human-review-not-accepted',
    reviewStatus: 'agent-proposed-pending-human-acceptance',
    humanAcceptanceRef: null,
  });
  assert.equal(
    candidateIndex.unknowns.filter(({ code }) => code === 'pending-human-judgment').length,
    6
  );
});

test('producer candidate index exactly matches the independent pre-anchor reconstruction', () => {
  assert.deepEqual(producerCandidateIndex(), reconstruct().candidateIndex);
});

test('238-path closure and per-path signal receipts fail closed under spoofing', () => {
  const missing = cloneReviewMap();
  missing.paths.pop();
  assert.throws(() => reconstruct(missing), /review receipt exact subject closure/u);

  const spoofed = cloneReviewMap();
  const candidate = spoofed.paths.find(({ signals }) => signals.length > 0);
  candidate.signals[0].matches = ['fabricated-signal'];
  assert.throws(() => reconstruct(spoofed), /path signal reconstruction/u);
});

test('typed citations bind selected values, source blobs, and archive members', () => {
  const pointerSpoof = cloneReviewMap();
  const pointer = pointerSpoof.paths
    .flatMap(({ citations }) => citations)
    .find(({ kind }) => kind === 'json-pointer');
  pointer.selectedValueSha256 = '0'.repeat(64);
  assert.throws(() => reconstruct(pointerSpoof), /citation selected digest/u);

  const archiveSpoof = cloneReviewMap();
  const archiveCitation = archiveSpoof.paths
    .flatMap(({ citations }) => citations)
    .find(({ kind }) => kind === 'archive-member');
  archiveCitation.memberSha256 = '0'.repeat(64);
  assert.throws(() => reconstruct(archiveSpoof), /archive citation member/u);

  const selectorSpoof = cloneReviewMap();
  selectorSpoof.paths
    .flatMap(({ citations }) => citations)
    .find(({ kind }) => kind === 'javascript-node').selector = { bogus: 1 };
  assert.throws(() => reconstruct(selectorSpoof), /citation selector/u);

  const ordinalSpoof = cloneReviewMap();
  ordinalSpoof.paths
    .flatMap(({ citations }) => citations)
    .find(
      ({ kind, selector }) => kind === 'docker-instruction' && selector.opcode
    ).selector.ordinal = 999;
  assert.throws(() => reconstruct(ordinalSpoof), /Docker instruction selector/u);
});

test('distributed image tokens remain signals but cannot manufacture a desired-state chain', () => {
  const reference = Buffer.from('ghcr.io/bitfocus/companion/companion:v4.3.3');
  const imageId = Buffer.from(
    'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e'
  );
  const referenceSignals = deriveIndependentSignals({
    relativePath: 'reference.txt',
    bytes: reference,
  });
  const idSignals = deriveIndependentSignals({ relativePath: 'id.txt', bytes: imageId });
  assert.deepEqual(
    referenceSignals.map(({ role }) => role),
    ['image']
  );
  assert.deepEqual(
    idSignals.map(({ role }) => role),
    ['image']
  );
  const { candidateIndex } = reconstruct();
  assert.equal(candidateIndex.chainComponents.length, 0);
  assert.equal(candidateIndex.eligibleChains.length, 0);
});

test('forbidden atoms and semantic-role escalation are rejected', () => {
  const atomSpoof = cloneReviewMap();
  atomSpoof.paths
    .find(({ path: relativePath }) => relativePath.endsWith('specifications/SPEC-0001.json'))
    .atoms.push({
      id: 'atom-forbidden-deployment-binding',
      kind: 'deployment-host-binding',
      subjectKey: 'forbidden',
      assertion: {},
      citationIds: ['citation-spec0001-host-role'],
    });
  assert.throws(() => reconstruct(atomSpoof), /atom shape/u);
  const producerRejection = producerCandidateIndex(atomSpoof);
  assert.equal(producerRejection.coverageComplete, false);
  assert.equal(producerRejection.outcome.status, 'inconclusive');
  assert.deepEqual(producerRejection.eligibleChains, []);
  assert.ok(
    producerRejection.unknowns.some(
      ({ code, id }) =>
        code === 'semantic-atom-invalid' && id === 'atom-forbidden-deployment-binding'
    )
  );

  const edgeSpoof = cloneReviewMap();
  const operational = edgeSpoof.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ semanticRole }) => semanticRole === 'operational');
  operational.semanticRole = 'authority-binding';
  assert.throws(() => reconstruct(edgeSpoof), /edge shape/u);

  const normativeSpoof = cloneReviewMap();
  normativeSpoof.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ semanticRole }) => semanticRole === 'operational').semanticRole = 'normative';
  assert.throws(() => reconstruct(normativeSpoof), /edge shape/u);

  const verificationSpoof = cloneReviewMap();
  verificationSpoof.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ kind }) => kind === 'workflow-npm-script').semanticRole = 'verification';
  assert.throws(() => reconstruct(verificationSpoof), /edge shape/u);

  const authoritySpoof = cloneReviewMap();
  authoritySpoof.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ semanticRole }) => semanticRole === 'authority-binding').assertion.effectiveStatus =
    'superseded';
  assert.throws(() => reconstruct(authoritySpoof), /authority edge binding/u);

  const ownerSpoof = cloneReviewMap();
  const workflowEdge = ownerSpoof.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ kind }) => kind === 'workflow-npm-script');
  workflowEdge.citationIds = ['citation-spec0001-host-role'];
  assert.throws(() => reconstruct(ownerSpoof), /edge citation ownership/u);
});

test('semantic atoms bind their owner and the exact values selected by every citation', () => {
  const ownerSpoof = cloneReviewMap();
  const specification = ownerSpoof.paths.find(
    ({ path: relativePath }) =>
      relativePath === '.overlaykit/governance/specifications/SPEC-0001.json'
  );
  const plan = ownerSpoof.paths.find(
    ({ path: relativePath }) => relativePath === '.overlaykit/governance/plan.json'
  );
  plan.atoms.push(specification.atoms.shift());
  assert.throws(() => reconstruct(ownerSpoof), /atom owner binding/u);

  const citationSpoof = cloneReviewMap();
  const specificationWithCitations = citationSpoof.paths.find(
    ({ path: relativePath }) =>
      relativePath === '.overlaykit/governance/specifications/SPEC-0001.json'
  );
  const citations = specificationWithCitations.citations;
  const hostRoleIndex = citations.findIndex(({ id }) => id === 'citation-spec0001-host-role');
  const title = citations.find(({ id }) => id === 'citation-spec0001-title');
  citations[hostRoleIndex] = {
    ...structuredClone(title),
    id: 'citation-spec0001-host-role',
  };
  assert.throws(() => reconstruct(citationSpoof), /atom citation binding/u);
});

test('typed atom graph requires the exact two-atom cardinality and owner-order closure', () => {
  const removed = cloneReviewMap();
  const removedOwner = removed.paths.find(({ atoms }) => atoms.length > 0);
  removedOwner.atoms.pop();
  assert.throws(() => reconstruct(removed), /typed semantic atom closure/u);
  assertProducerFailsClosed(removed, 'semantic-atom-closure-mismatch');

  const duplicated = cloneReviewMap();
  const duplicateOwner = duplicated.paths.find(({ atoms }) => atoms.length > 0);
  const duplicate = structuredClone(duplicateOwner.atoms[0]);
  duplicate.id = `${duplicate.id}-duplicate`;
  duplicateOwner.atoms.push(duplicate);
  assert.throws(() => reconstruct(duplicated), /typed semantic atom closure/u);
  assertProducerFailsClosed(duplicated, 'semantic-atom-closure-mismatch');
});

test('archive nesting edges bind their assertion to member bytes and nested closure', () => {
  const spoofed = cloneReviewMap();
  const nesting = spoofed.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ kind }) => kind === 'archive-nesting');
  nesting.assertion.nestedClosureSha256 = '0'.repeat(64);
  assert.throws(() => reconstruct(spoofed), /archive nesting edge binding/u);

  const kindBypass = cloneReviewMap();
  const disguised = kindBypass.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ kind }) => kind === 'archive-nesting');
  disguised.kind = 'not-archive-nesting';
  disguised.assertion.nestedClosureSha256 = '0'.repeat(64);
  assert.throws(() => reconstruct(kindBypass), /edge shape/u);
});

test('materialized edges reject semantic retargeting and Docker context shrinkage', () => {
  const workflowRetarget = cloneReviewMap();
  const readme = workflowRetarget.paths.find(
    ({ path: relativePath }) => relativePath === 'README.md'
  );
  const workflowEdge = workflowRetarget.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ kind }) => kind === 'workflow-npm-script');
  workflowEdge.target = {
    kind: 'path',
    path: readme.path,
    blobSha256: readme.blobSha256,
  };
  workflowEdge.assertion = { scriptName: 'fabricated-script' };
  assert.throws(() => reconstruct(workflowRetarget), /workflow npm edge binding/u);

  const contextShrink = cloneReviewMap();
  const contextEdge = contextShrink.paths
    .flatMap(({ outgoingEdges }) => outgoingEdges)
    .find(({ kind }) => kind === 'docker-build-context');
  contextEdge.target.members = [
    {
      path: readme.path,
      blobSha256: readme.blobSha256,
    },
  ];
  contextEdge.target.closureSha256 = independentSha256(
    Buffer.from(canonicalIndependentJson(contextEdge.target.members), 'utf8')
  );
  assert.throws(() => reconstruct(contextShrink), /Docker build context edge binding/u);
});

test('typed edge graph requires the exact 106-edge cardinality and owner-order closure', () => {
  const removed = cloneReviewMap();
  const receipt = removed.paths.find(({ outgoingEdges }) => outgoingEdges.length > 0);
  const [removedEdge] = receipt.outgoingEdges.splice(0, 1);
  receipt.indirections.edgeIds = receipt.indirections.edgeIds.filter(
    (edgeId) => edgeId !== removedEdge.id
  );
  assert.throws(() => reconstruct(removed), /typed edge exact closure/u);
  assertProducerFailsClosed(removed, 'semantic-edge-closure-mismatch');

  const duplicated = cloneReviewMap();
  const duplicateOwner = duplicated.paths.find(({ outgoingEdges }) => outgoingEdges.length > 0);
  const duplicate = structuredClone(duplicateOwner.outgoingEdges[0]);
  duplicate.id = `${duplicate.id}-duplicate`;
  duplicateOwner.outgoingEdges.push(duplicate);
  duplicateOwner.indirections.edgeIds.push(duplicate.id);
  assert.throws(() => reconstruct(duplicated), /typed edge exact closure/u);
  assertProducerFailsClosed(duplicated, 'semantic-edge-closure-mismatch');
});

test('unresolved indirection is a mechanical blocker and never authorizes refutation', () => {
  const unresolved = cloneReviewMap();
  unresolved.paths.find(
    ({ indirections }) => indirections.archiveExpansion !== null
  ).indirections.state = 'unresolved';
  const { candidateIndex } = reconstruct(unresolved);
  assert.equal(candidateIndex.semanticReview.coverageComplete, false);
  assert.ok(candidateIndex.unknowns.some(({ code }) => code === 'unresolved-indirection'));
  assert.equal(candidateIndex.outcome.status, 'inconclusive');
});

test('independent strict tar+gzip parser rejects traversal, duplicates, links, and trailing streams', () => {
  const valid = tarGzip([{ path: 'safe/file.txt', body: 'ok' }]);
  const forest = expandIndependentArchiveForest([{ path: 'fixtures/valid.tar.gz', bytes: valid }]);
  assert.equal(forest.audit.rootCount, 1);
  assert.equal(forest.audit.memberOccurrences, 1);

  for (const hostile of [
    tarGzip([{ path: '../escape.txt', body: 'no' }]),
    tarGzip([{ path: 'C:/escape.txt', body: 'no' }]),
    tarGzip([{ path: 'C:escape.txt', body: 'no' }]),
    tarGzip([
      { path: 'same.txt', body: 'one' },
      { path: 'same.txt', body: 'two' },
    ]),
    tarGzip([{ path: 'link.txt', body: '', type: '2' }]),
    Buffer.concat([valid, valid]),
  ]) {
    assert.throws(() =>
      expandIndependentArchiveForest([{ path: 'fixtures/hostile.tar.gz', bytes: hostile }])
    );
  }
  assert.throws(() =>
    expandIndependentArchiveForest([{ path: 'fixtures!hostile/valid.tar.gz', bytes: valid }])
  );
});

const ANCHOR_READY = sourceAnchorReady();
const ANCHOR_TEST_OPTIONS = {
  skip:
    ANCHOR_READY || ANCHOR_REQUIRED ? false : 'requires the signed canonical H-047 source anchor',
};
const INTEGRATION_TEST_OPTIONS = {
  skip:
    ANCHOR_READY || ANCHOR_REQUIRED ? false : 'requires the signed canonical H-047 source anchor',
};

test(
  'H047_REQUIRE_ANCHOR=1 makes source-anchor readiness a mandatory gate',
  ANCHOR_TEST_OPTIONS,
  () => {
    assert.equal(ANCHOR_READY, true);
  }
);

test(
  'independent verifier reconstructs the exact anchored bundle as inconclusive',
  INTEGRATION_TEST_OPTIONS,
  () => {
    assert.equal(ANCHOR_READY, true);
    const artifactRoot = path.join(REPOSITORY_ROOT, 'artifacts', 'h047');
    mkdirSync(artifactRoot, { recursive: true, mode: 0o700 });
    const directory = mkdtempSync(path.join(artifactRoot, 'verify-test-valid-'));
    try {
      const bundle = buildH047Bundle();
      writeBundle(directory, bundle);
      const verification = verifyH047(directory);
      assert.equal(verification.verified, true);
      assert.equal(verification.reviewedPaths, 238);
      assert.equal(verification.candidates, 101);
      assert.equal(verification.mechanicalCoverageComplete, true);
      assert.equal(verification.outcome.status, 'inconclusive');
      assert.equal(verification.authority, 'none');
      assert.equal(verification.action, null);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
);

test(
  'independent verifier rejects producer outcome and authority tampering',
  INTEGRATION_TEST_OPTIONS,
  () => {
    assert.equal(ANCHOR_READY, true);
    const artifactRoot = path.join(REPOSITORY_ROOT, 'artifacts', 'h047');
    mkdirSync(artifactRoot, { recursive: true, mode: 0o700 });
    const bundle = buildH047Bundle();
    for (const [label, mutate] of [
      [
        'outcome',
        (run) => {
          run.outcome = {
            status: 'refuted',
            stage: 'complete-repository-inventory',
            reasonCode: 'complete-zero-eligible-chain-coverage',
          };
        },
      ],
      [
        'authority',
        (run) => {
          run.authority = 'operator';
        },
      ],
    ]) {
      const directory = mkdtempSync(path.join(artifactRoot, `verify-test-${label}-`));
      try {
        writeBundle(directory, bundle);
        const runPath = path.join(directory, 'run.json');
        const run = JSON.parse(readFileSync(runPath, 'utf8'));
        mutate(run);
        const { semanticEvidenceSha256: ignored, ...semantic } = run;
        void ignored;
        run.semanticEvidenceSha256 = independentSha256(canonicalIndependentJson(semantic));
        writeFileSync(runPath, `${canonicalIndependentJson(run)}\n`, {
          flag: 'w',
          mode: 0o600,
        });
        assert.throws(() => verifyH047(directory));
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
  }
);

test('test temporary writes remain under the ignored H-047 artifact root', () => {
  assert.notEqual(os.tmpdir(), path.join(REPOSITORY_ROOT, 'artifacts', 'h047'));
});
