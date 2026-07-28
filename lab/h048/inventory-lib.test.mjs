import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { expandTarGzipForest } from './archive-lib.mjs';
import {
  H048_PREDICATES,
  admitSetAnchor,
  assertGitBlobIdentity,
  assembleDesiredStateChains,
  canonicalJson,
  createGitReader,
  deriveReviewUniverse,
  deriveOutcome,
  framedSetSha256,
  indirectionsFromBytes,
  parseLsTreeZ,
  reviewPayloadSha256,
  scanSignals,
  sha256,
  validateHumanAcceptance,
  validateReviewMap,
} from './inventory-lib.mjs';

const LOCK = Object.freeze({
  key: 'OverlayKit/example',
  commit: '1'.repeat(40),
  tree: '2'.repeat(40),
});
const SUBJECT_REPOSITORIES = Object.freeze([
  Object.freeze({
    key: 'OverlayKit/companion-module-overlaykit-server',
    commit: '2d46d1c60e7aced224b47a8857d93015c5fb5c91',
  }),
  Object.freeze({
    key: 'OverlayKit/overlaykit',
    commit: '9a5585de196ff972993c7ff81bf9c1461c47eaae',
  }),
]);
const TARGET = Object.freeze({
  imageReference: 'ghcr.io/bitfocus/companion/companion:v4.3.3',
  imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
  hostRole: 'spec-0001-linux-production-host',
});

function treeRecord(mode, oid, repositoryPath) {
  return Buffer.from(`${mode} blob ${oid}\t${repositoryPath}\0`, 'utf8');
}

function writeTarString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  assert.ok(bytes.length <= length);
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  writeTarString(header, offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`);
}

function tarEntry(name, body = Buffer.alloc(0), type = '0', mode = 0o644) {
  const bytes = Buffer.from(body);
  const header = Buffer.alloc(512);
  writeTarString(header, 0, 100, name);
  writeTarOctal(header, 100, 8, mode);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, bytes.length);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeTarString(header, 257, 6, 'ustar\0');
  writeTarString(header, 263, 2, '00');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeTarString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  const padding = Buffer.alloc((512 - (bytes.length % 512)) % 512);
  return Buffer.concat([header, bytes, padding]);
}

function tarGzip(entries, terminator = Buffer.alloc(1024)) {
  return gzipSync(Buffer.concat([...entries, terminator]), { mtime: 0 });
}

test('locks the eight H-048 predicates in semantic order', () => {
  assert.deepEqual(H048_PREDICATES, [
    'effectiveAcceptedProductionAuthority',
    'exactImageReferenceAndId',
    'spec0001LinuxHostBinding',
    'deploymentPresenceAndCardinality',
    'repositoryDeclaredLifecycleOwner',
    'reconcilerMechanism',
    'absenceToConvergenceRule',
    'explicitLinkClosure',
  ]);
  assert.equal(new Set(H048_PREDICATES).size, 8);
});

test('canonical JSON and SHA-256 are independent of object key insertion order', () => {
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
  assert.equal(
    sha256(Buffer.from(canonicalJson({ b: 2, a: 1 }))),
    sha256(Buffer.from(canonicalJson({ a: 1, b: 2 })))
  );
});

test('parses exact NUL-safe blob trees and rejects unsafe or ambiguous records', () => {
  const first = treeRecord('100644', '1'.repeat(40), 'a/file.json');
  const second = treeRecord('100755', '2'.repeat(40), 'bin/run');
  assert.deepEqual(parseLsTreeZ(Buffer.concat([first, second])), [
    {
      mode: '100644',
      type: 'blob',
      oid: '1'.repeat(40),
      path: 'a/file.json',
    },
    {
      mode: '100755',
      type: 'blob',
      oid: '2'.repeat(40),
      path: 'bin/run',
    },
  ]);
  for (const bytes of [
    Buffer.from('100644 blob ' + '1'.repeat(40) + '\ta/file.json'),
    treeRecord('100664', '1'.repeat(40), 'a/file.json'),
    treeRecord('100644', '1'.repeat(40), '../escape'),
    treeRecord('100644', '1'.repeat(40), 'a!member'),
    Buffer.concat([first, first]),
  ]) {
    assert.throws(() => parseLsTreeZ(bytes));
  }
});

test('repository-qualified framing prevents equal relative paths from aliasing', () => {
  const base = {
    path: 'README.md',
    mode: '100644',
    byteLength: 1,
    sha256: 'a'.repeat(64),
  };
  const left = framedSetSha256([{ repository: 'OverlayKit/a', ...base }]);
  const right = framedSetSha256([{ repository: 'OverlayKit/b', ...base }]);
  assert.notEqual(left, right);
  assert.throws(
    () =>
      framedSetSha256([
        { repository: 'OverlayKit/a', ...base },
        { repository: 'OverlayKit/a', ...base },
      ]),
    /duplicate framed identity/u
  );
});

test('Git blob bytes must reproduce the exact ls-tree object ID', () => {
  const bytes = Buffer.from('exact git blob fixture\n', 'utf8');
  const oid = createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');
  assert.doesNotThrow(() => assertGitBlobIdentity(oid, bytes));
  assert.throws(
    () => assertGitBlobIdentity(oid, Buffer.from('substituted bytes', 'utf8')),
    /object identity differs/u
  );
});

test('H-048 dependency-free archive decoder closes forests and rejects unsafe structures', () => {
  const nested = tarGzip([tarEntry('inside.txt', 'nested')]);
  const root = tarGzip([tarEntry('plain.txt', 'plain'), tarEntry('nested/replay.tar.gz', nested)]);
  const forest = expandTarGzipForest([{ path: 'evidence/root.tar.gz', bytes: root }]);
  assert.equal(forest.observations.archives, 2);
  assert.equal(forest.observations.regularMembers, 3);
  assert.equal(forest.members.length, 3);
  assert.equal(
    forest.archives.some((archive) => archive.depth === 1),
    true
  );
  for (const [hostilePath, expected] of [
    ['../escape', /member path/u],
    ['/absolute', /member path/u],
    ['nested//empty', /member path/u],
    ['literal!/inside.txt', /reserved route delimiter/u],
  ]) {
    assert.throws(
      () =>
        expandTarGzipForest([
          {
            path: 'evidence/hostile.tar.gz',
            bytes: tarGzip([tarEntry(hostilePath, 'unsafe')]),
          },
        ]),
      expected
    );
  }
  assert.throws(
    () =>
      expandTarGzipForest([
        {
          path: 'evidence/link.tar.gz',
          bytes: tarGzip([tarEntry('link', '', '2')]),
        },
      ]),
    /strict profile rejects tar member type/u
  );
  assert.throws(
    () => expandTarGzipForest([{ path: 'evidence/root.tar.gz', bytes: root }], { maxArchives: 1 }),
    /archive count exceeds/u
  );
  assert.throws(
    () =>
      expandTarGzipForest([
        {
          path: 'evidence/mismatch.tar.gz',
          bytes: tarGzip([tarEntry('declared.tar.gz', 'not-gzip')]),
        },
      ]),
    /extension\/signature mismatch/u
  );
});

test('set admission distinguishes opaque, exact, and mismatched preimages', () => {
  const bytes = Buffer.from('explicit future human-nominated set manifest', 'utf8');
  const digest = sha256(bytes);
  assert.deepEqual(
    admitSetAnchor(
      {
        sha256: digest,
        preimageStatus: 'unavailable',
        canonicalization: null,
        preimage: null,
      },
      'fixture'
    ),
    {
      admitted: false,
      reasonCode: 'accepted-source-anchor-opaque',
      sha256: digest,
    }
  );
  assert.deepEqual(
    admitSetAnchor(
      {
        sha256: digest,
        preimageStatus: 'available',
        canonicalization: 'exact-base64-decoded-bytes/v1',
        preimage: bytes.toString('base64'),
      },
      'fixture'
    ),
    {
      admitted: true,
      reasonCode: 'exact-preimage-admitted',
      sha256: digest,
      byteLength: bytes.length,
    }
  );
  assert.throws(
    () =>
      admitSetAnchor({
        sha256: 'a'.repeat(64),
        preimageStatus: 'available',
        canonicalization: 'exact-base64-decoded-bytes/v1',
        preimage: bytes.toString('base64'),
      }),
    /preimage digest differs/u
  );
  assert.throws(
    () =>
      admitSetAnchor({
        sha256: digest,
        preimageStatus: 'available',
        canonicalization: 'invented-json/v1',
        preimage: bytes.toString('base64'),
      }),
    /canonicalization is unsupported/u
  );
});

test('human review acceptance is embedded, content-addressed, and boundary-bound', () => {
  const subjectLockBytes = readFileSync(new URL('./subject-lock.json', import.meta.url));
  const subjectLock = JSON.parse(subjectLockBytes);
  const pending = JSON.parse(readFileSync(new URL('./review-map.json', import.meta.url), 'utf8'));
  assert.deepEqual(
    validateHumanAcceptance({
      reviewMap: pending,
      subjectLock,
      subjectLockBytes,
      expectedReviewUniverse: pending.reviewUniverse,
    }),
    {
      accepted: false,
      payloadSha256: reviewPayloadSha256(pending),
      acceptanceReceiptSha256: null,
    }
  );
  const acceptedDraft = {
    ...pending,
    status: 'human-accepted',
    humanAcceptanceRef: null,
    pendingHumanJudgments: [],
  };
  const acceptance = {
    schemaVersion: 'overlaykit-h048-human-acceptance/v1',
    hypothesis: 'H-048',
    principal: '@rodrigoteamx',
    reviewPayloadSha256: reviewPayloadSha256(acceptedDraft),
    subjectLockRawSha256: sha256(subjectLockBytes),
    subjectLockCanonicalSha256: sha256(Buffer.from(canonicalJson(subjectLock), 'utf8')),
    claimBoundaryCanonicalSha256: sha256(
      Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
    ),
    repoSetSha256: subjectLock.repoSet.sha256,
    reviewUniverseSha256: acceptedDraft.reviewUniverse.sha256,
    authority: 'none',
    action: null,
  };
  const bytes = Buffer.from(`${canonicalJson(acceptance)}\n`, 'utf8');
  const accepted = {
    ...acceptedDraft,
    humanAcceptanceRef: {
      kind: 'embedded-content-addressed-json',
      canonicalization: 'exact-base64-decoded-bytes/v1',
      byteLength: bytes.length,
      sha256: sha256(bytes),
      preimageBase64: bytes.toString('base64'),
    },
  };
  assert.throws(
    () =>
      validateHumanAcceptance({
        reviewMap: accepted,
        subjectLock,
        subjectLockBytes,
        expectedReviewUniverse: accepted.reviewUniverse,
      }),
    /externally nominated digest/u
  );
  assert.equal(
    validateHumanAcceptance({
      reviewMap: accepted,
      subjectLock,
      subjectLockBytes,
      expectedReviewUniverse: accepted.reviewUniverse,
      expectedAcceptanceSha256: accepted.humanAcceptanceRef.sha256,
    }).accepted,
    true
  );
  for (const mutate of [
    (value) => {
      value.humanAcceptanceRef.byteLength += 1;
    },
    (value) => {
      value.humanAcceptanceRef.sha256 = 'a'.repeat(64);
    },
    (value) => {
      const hostile = { ...acceptance, principal: '@attacker' };
      const hostileBytes = Buffer.from(`${canonicalJson(hostile)}\n`, 'utf8');
      value.humanAcceptanceRef = {
        ...value.humanAcceptanceRef,
        byteLength: hostileBytes.length,
        sha256: sha256(hostileBytes),
        preimageBase64: hostileBytes.toString('base64'),
      };
    },
    (value) => {
      const hostile = { ...acceptance, reviewUniverseSha256: 'b'.repeat(64) };
      const hostileBytes = Buffer.from(`${canonicalJson(hostile)}\n`, 'utf8');
      value.humanAcceptanceRef = {
        ...value.humanAcceptanceRef,
        byteLength: hostileBytes.length,
        sha256: sha256(hostileBytes),
        preimageBase64: hostileBytes.toString('base64'),
      };
    },
  ]) {
    const hostile = structuredClone(accepted);
    mutate(hostile);
    assert.throws(() =>
      validateHumanAcceptance({
        reviewMap: hostile,
        subjectLock,
        subjectLockBytes,
        expectedReviewUniverse: accepted.reviewUniverse,
        expectedAcceptanceSha256: hostile.humanAcceptanceRef.sha256,
      })
    );
  }
});

function semanticReviewFixture() {
  const subjectLockBytes = readFileSync(new URL('./subject-lock.json', import.meta.url));
  const subjectLock = JSON.parse(subjectLockBytes);
  const sourceBytes = Buffer.from(
    'deployment-alpha binds accepted authority and exact image identity',
    'utf8'
  );
  const sourceSha256 = sha256(sourceBytes);
  const source = {
    repository: subjectLock.repositories[0].key,
    commit: subjectLock.repositories[0].commit,
    path: 'policy/deployment-alpha.txt',
    sourceKind: 'git-blob',
    sha256: sourceSha256,
    classification: 'fixture-human-reviewed',
    predicateContributions: ['effectiveAcceptedProductionAuthority', 'exactImageReferenceAndId'],
    eligibleForChain: true,
    rationale: 'Hostile-test fixture.',
  };
  const binding = {
    deploymentKey: 'deployment-alpha',
    imageReference: subjectLock.target.imageReference,
    imageId: subjectLock.target.imageId,
    hostRole: subjectLock.target.hostRole,
  };
  const bindingEvidence = {
    kind: 'exact-utf8-byte-span/v1',
    byteOffset: 0,
    byteLength: Buffer.byteLength(binding.deploymentKey),
    sha256: sha256(Buffer.from(binding.deploymentKey, 'utf8')),
  };
  const chainContributions = source.predicateContributions
    .map((predicate) => ({
      repository: source.repository,
      commit: source.commit,
      path: source.path,
      sourceKind: source.sourceKind,
      sha256: source.sha256,
      predicate,
      disposition: 'supports',
      binding,
      bindingEvidence,
    }))
    .sort((left, right) =>
      Buffer.compare(
        Buffer.from(canonicalJson(left), 'utf8'),
        Buffer.from(canonicalJson(right), 'utf8')
      )
    );
  const reviewMap = {
    schemaVersion: 'overlaykit-h048-semantic-review/v1',
    hypothesis: 'H-048',
    status: 'agent-proposed-pending-human-acceptance',
    humanAcceptanceRef: null,
    reviewUniverse: null,
    defaultDisposition: {
      classification: 'no-eligible-predicate-contribution',
      rationale: 'Fixture default.',
      authority: 'none',
      action: null,
    },
    defaultIndirectionDisposition: {
      classification: 'no-eligible-semantic-indirection',
      rationale: 'Fixture indirection default.',
      authority: 'none',
      action: null,
    },
    sources: [source],
    chainContributions,
    pendingHumanJudgments: ['review the complete fixture'],
    authority: 'none',
    action: null,
  };
  const oid = '1'.repeat(40);
  const snapshots = [
    {
      repository: source.repository,
      commit: source.commit,
      plan: { decisions: [], specifications: [] },
      sourceEntries: [
        {
          path: source.path,
          mode: '100644',
          oid,
          byteLength: sourceBytes.length,
          sha256: source.sha256,
        },
      ],
      blobsByOid: new Map([[oid, sourceBytes]]),
    },
    {
      repository: subjectLock.repositories[1].key,
      commit: subjectLock.repositories[1].commit,
      plan: { decisions: [], specifications: [] },
      sourceEntries: [],
      blobsByOid: new Map(),
    },
  ];
  const archiveInventory = {
    members: [],
    memberContents: new Map(),
  };
  reviewMap.reviewUniverse = deriveReviewUniverse({
    subjectLock,
    snapshots,
    archiveInventory,
  }).reference;
  return {
    reviewMap,
    subjectLock,
    subjectLockBytes,
    snapshots,
    archiveInventory,
  };
}

test('semantic review admission binds exact source identity, ordering, eligibility, and byte span', () => {
  const fixture = semanticReviewFixture();
  assert.equal(validateReviewMap(fixture).chainContributions.length, 2);
  for (const mutate of [
    (value) => {
      value.reviewMap.sources[0].commit = '1'.repeat(40);
    },
    (value) => {
      value.reviewMap.reviewUniverse.sha256 = 'a'.repeat(64);
    },
    (value) => {
      value.reviewMap.reviewUniverse.sourceCount += 1;
    },
    (value) => {
      value.reviewMap.sources[0].sourceKind = 'archive-member';
    },
    (value) => {
      value.reviewMap.sources[0].sha256 = 'a'.repeat(64);
    },
    (value) => {
      value.reviewMap.sources[0].eligibleForChain = false;
    },
    (value) => {
      value.reviewMap.sources[0].extra = true;
    },
    (value) => {
      value.reviewMap.chainContributions[0].bindingEvidence.byteOffset = 1;
    },
    (value) => {
      value.reviewMap.chainContributions.reverse();
    },
  ]) {
    const hostile = {
      ...fixture,
      reviewMap: structuredClone(fixture.reviewMap),
    };
    mutate(hostile);
    assert.throws(() => validateReviewMap(hostile));
  }
});

test('indirections resolve only atomic nominated repo-plus-commit URLs', () => {
  const owner = {
    repository: SUBJECT_REPOSITORIES[0].key,
    ownerCommit: SUBJECT_REPOSITORIES[0].commit,
    repositoryPath: 'policy.md',
    sourceKind: 'git-blob',
    sourceSha256: 'a'.repeat(64),
    subjectRepositories: SUBJECT_REPOSITORIES,
  };
  const receipts = indirectionsFromBytes({
    ...owner,
    bytes: Buffer.from(
      [
        `https://github.com/OverlayKit/overlaykit/commit/${SUBJECT_REPOSITORIES[1].commit}`,
        'https://github.com/OverlayKit/overlaykit',
        'https://github.com/OverlayKit/overlaykit/issues/1',
        `https://github.com/OverlayKit/overlaykit/tree/${'1'.repeat(40)}`,
        'https://github.com/OverlayKit/overlaykit/pull/42',
        'https://example.com/policy',
        'OverlayKit/overlaykit',
        SUBJECT_REPOSITORIES[1].commit,
      ].join('\n')
    ),
  });
  assert.equal(receipts.filter((receipt) => receipt.status === 'resolved-exact-subject').length, 1);
  assert.ok(receipts.some((receipt) => receipt.status === 'unversioned-subject-reference'));
  assert.ok(receipts.some((receipt) => receipt.status === 'unscoped-commit-reference'));
  assert.ok(receipts.some((receipt) => receipt.status === 'subject-commit-mismatch'));
  assert.ok(receipts.some((receipt) => receipt.status === 'excluded-github-surface'));
  assert.ok(receipts.some((receipt) => receipt.status === 'unresolved-github-pull-request'));
  assert.ok(receipts.some((receipt) => receipt.status === 'excluded-outside-nominated-boundary'));
  for (const receipt of receipts) {
    const { id, ...body } = receipt;
    assert.equal(id, sha256(Buffer.from(canonicalJson(body), 'utf8')));
    if (receipt.status === 'resolved-exact-subject') {
      assert.notEqual(receipt.targetRepository, null);
      assert.notEqual(receipt.targetCommit, null);
    }
  }
});

test('indirections fail closed for spoofed and noncanonical subject URLs', () => {
  const exactCommit = SUBJECT_REPOSITORIES[1].commit;
  const receipts = indirectionsFromBytes({
    repository: SUBJECT_REPOSITORIES[0].key,
    ownerCommit: SUBJECT_REPOSITORIES[0].commit,
    repositoryPath: 'hostile-links.md',
    sourceKind: 'git-blob',
    sourceSha256: 'e'.repeat(64),
    subjectRepositories: SUBJECT_REPOSITORIES,
    bytes: Buffer.from(
      [
        `https://codeload.github.com/OverlayKit/overlaykit/tar.gz/${exactCommit}`,
        `http://github.com/OverlayKit/overlaykit/commit/${exactCommit}`,
        `https://github.com@evil.example/OverlayKit/overlaykit/commit/${exactCommit}`,
        `https://github.com/overlaykit/overlaykit/commit/${exactCommit}`,
        `https://github.com/OverlayKit/not-a-subject/commit/${exactCommit}`,
        'https://codeload.github.com/OverlayKit/overlaykit/legacy.tar.gz/main',
        'https://github.com/OverlayKit/overlaykit.git',
        'https://github.com/OverlayKit/overlaykit#readme',
        `https://GITHUB.com/OverlayKit/overlaykit/commit/${exactCommit}`,
      ].join('\n')
    ),
  });
  assert.equal(receipts.length, 9);
  assert.equal(receipts.filter((receipt) => receipt.status === 'resolved-exact-subject').length, 1);
  assert.equal(
    receipts.filter((receipt) => receipt.status === 'excluded-outside-nominated-boundary').length,
    2
  );
  assert.equal(
    receipts.filter((receipt) => receipt.status === 'unversioned-subject-reference').length,
    6
  );
  for (const receipt of receipts.filter(
    (candidate) => candidate.kind === 'subject-noncanonical-url'
  )) {
    assert.equal(receipt.status, 'unversioned-subject-reference');
    assert.equal(receipt.targetRepository, SUBJECT_REPOSITORIES[1].key);
    assert.equal(receipt.targetCommit, null);
  }
});

function chainFixture(bindingKey = 'overlaykit-companion-production') {
  const binding = {
    deploymentKey: bindingKey,
    ...TARGET,
  };
  const candidates = H048_PREDICATES.map((predicate, index) => {
    const subject = SUBJECT_REPOSITORIES[index % SUBJECT_REPOSITORIES.length];
    return {
      repository: subject.key,
      commit: subject.commit,
      path: `policy/${bindingKey}/${String(index).padStart(2, '0')}-${predicate}.json`,
      sourceKind: 'git-blob',
      sha256: sha256(Buffer.from(`${bindingKey}:${predicate}`, 'utf8')),
      classification: 'fixture-human-reviewed',
      predicateContributions: [predicate],
      eligibleForChain: true,
    };
  });
  const chainContributions = candidates.map((candidate, index) => ({
    repository: candidate.repository,
    commit: candidate.commit,
    path: candidate.path,
    sourceKind: candidate.sourceKind,
    sha256: candidate.sha256,
    predicate: H048_PREDICATES[index],
    disposition: 'supports',
    binding,
    bindingEvidence: {
      kind: 'exact-utf8-byte-span/v1',
      byteOffset: 0,
      byteLength: Buffer.byteLength(bindingKey, 'utf8'),
      sha256: sha256(Buffer.from(bindingKey, 'utf8')),
    },
  }));
  const linkSource = candidates.at(-1);
  const linkBody = {
    ownerRepository: linkSource.repository,
    ownerCommit: linkSource.commit,
    ownerPath: linkSource.path,
    ownerSourceKind: linkSource.sourceKind,
    ownerSha256: linkSource.sha256,
    kind: 'subject-atomic-url',
    value: `https://github.com/OverlayKit/companion-module-overlaykit-server/commit/${SUBJECT_REPOSITORIES[0].commit}`,
    targetRepository: SUBJECT_REPOSITORIES[0].key,
    targetCommit: SUBJECT_REPOSITORIES[0].commit,
    status: 'resolved-exact-subject',
  };
  return {
    binding,
    candidates,
    chainContributions,
    indirections: [
      {
        id: sha256(Buffer.from(canonicalJson(linkBody), 'utf8')),
        ...linkBody,
      },
    ],
  };
}

test('typed assembler emits one stable complete chain and never mixes bindings', () => {
  const complete = chainFixture();
  const first = assembleDesiredStateChains({
    ...complete,
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  const reordered = assembleDesiredStateChains({
    ...complete,
    chainContributions: [...complete.chainContributions].reverse(),
    candidates: [...complete.candidates].reverse(),
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  assert.equal(first.eligibleChains.length, 1);
  assert.equal(first.unknowns.length, 0);
  assert.equal(canonicalJson(first), canonicalJson(reordered));

  const left = chainFixture('binding-left');
  const right = chainFixture('binding-right');
  const split = assembleDesiredStateChains({
    chainContributions: [
      ...left.chainContributions.slice(0, 4),
      ...right.chainContributions.slice(4),
    ],
    candidates: [...left.candidates.slice(0, 4), ...right.candidates.slice(4)],
    indirections: left.indirections,
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  assert.equal(split.eligibleChains.length, 0);
  assert.equal(split.chainAssessments.length, 2);
});

test('typed assembler preserves multiple complete bindings as independent chains', () => {
  const left = chainFixture('binding-left');
  const right = chainFixture('binding-right');
  const result = assembleDesiredStateChains({
    chainContributions: [...left.chainContributions, ...right.chainContributions],
    candidates: [...left.candidates, ...right.candidates],
    indirections: [...left.indirections, ...right.indirections],
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  assert.equal(result.unknowns.length, 0);
  assert.equal(result.chainAssessments.length, 2);
  assert.equal(result.eligibleChains.length, 2);
  assert.equal(new Set(result.eligibleChains.map((chain) => chain.chainKey)).size, 2);
});

test('typed assembler fails closed on duplicate support, contradiction, and borrowed link', () => {
  const fixture = chainFixture();
  const duplicateCandidate = {
    ...fixture.candidates[0],
    path: 'policy/duplicate-authority.json',
    sha256: 'f'.repeat(64),
  };
  const duplicateContribution = {
    ...fixture.chainContributions[0],
    path: duplicateCandidate.path,
    sha256: duplicateCandidate.sha256,
  };
  const ambiguous = assembleDesiredStateChains({
    ...fixture,
    candidates: [...fixture.candidates, duplicateCandidate],
    chainContributions: [...fixture.chainContributions, duplicateContribution],
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  assert.equal(ambiguous.eligibleChains.length, 0);
  assert.ok(ambiguous.unknowns.some((unknown) => unknown.code === 'ambiguous-chain-component'));

  const contradiction = assembleDesiredStateChains({
    ...fixture,
    chainContributions: [
      ...fixture.chainContributions,
      { ...fixture.chainContributions[0], disposition: 'contradicts' },
    ],
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  assert.equal(contradiction.eligibleChains.length, 0);
  assert.ok(
    contradiction.unknowns.some((unknown) => unknown.code === 'contradictory-chain-component')
  );

  const borrowedBody = {
    ...fixture.indirections[0],
    ownerPath: fixture.candidates[0].path,
    ownerSha256: fixture.candidates[0].sha256,
  };
  delete borrowedBody.id;
  const borrowed = assembleDesiredStateChains({
    ...fixture,
    indirections: [
      {
        id: sha256(Buffer.from(canonicalJson(borrowedBody), 'utf8')),
        ...borrowedBody,
      },
    ],
    subjectRepositories: SUBJECT_REPOSITORIES,
    target: TARGET,
    reviewAccepted: true,
  });
  assert.equal(borrowed.eligibleChains.length, 0);
  assert.ok(borrowed.unknowns.some((unknown) => unknown.code === 'explicit-link-not-exact'));
});

test('Git reader rejects mutation and network commands before spawning', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'h048-reader-'));
  try {
    let called = false;
    const reader = createGitReader({
      root,
      repositoryLock: LOCK,
      spawn() {
        called = true;
        throw new Error('spawn must not run');
      },
    });
    for (const command of [
      ['fetch'],
      ['pull'],
      ['checkout', 'main'],
      ['reset', '--hard'],
      ['status'],
      ['for-each-ref'],
      ['ls-tree', '-rz', '--full-tree', 'HEAD'],
      ['rev-parse', 'HEAD^{tree}'],
      ['cat-file', '-p', '1'.repeat(40)],
    ]) {
      assert.throws(() => reader.git(command), /outside the H-048 allowlist/u);
    }
    assert.equal(called, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Git reader admits only exact object reads with zero environment inheritance', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'h048-reader-'));
  const invocations = [];
  try {
    const reader = createGitReader({
      root,
      repositoryLock: LOCK,
      spawn(executable, args, options) {
        invocations.push({ executable, args, options });
        return {
          error: undefined,
          status: 0,
          signal: null,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        };
      },
    });
    reader.git(['cat-file', 'blob', '3'.repeat(40)]);
    reader.git(['ls-tree', '-rz', '--full-tree', LOCK.commit]);
    reader.git(['rev-parse', `${LOCK.commit}^{tree}`]);
    assert.deepEqual(reader.counts(), {
      'cat-file-blob': 1,
      'ls-tree': 1,
      'rev-parse-tree': 1,
    });
    for (const invocation of invocations) {
      assert.equal(invocation.executable, '/usr/bin/git');
      assert.equal(Object.hasOwn(invocation.options.env, 'HOME'), false);
      assert.equal(Object.hasOwn(invocation.options.env, 'GITHUB_TOKEN'), false);
      assert.deepEqual(invocation.options.env, {
        GIT_CONFIG_COUNT: '0',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_NO_LAZY_FETCH: '1',
        GIT_NO_REPLACE_OBJECTS: '1',
        GIT_OPTIONAL_LOCKS: '0',
        GIT_TERMINAL_PROMPT: '0',
        LANG: 'C',
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('semantic scan distinguishes exact identity from lifecycle claims', () => {
  const identity = scanSignals(
    Buffer.from(
      'ghcr.io/bitfocus/companion/companion:v4.3.3 sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e'
    ),
    'record.json'
  );
  assert.ok(identity.roles.includes('exact-image-reference'));
  assert.ok(identity.roles.includes('exact-image-id'));
  assert.equal(identity.roles.includes('reconciler-language'), false);

  const lifecycle = scanSignals(
    Buffer.from('A lifecycle owner reconciler must restart when the deployment is absent.'),
    'policy.md'
  );
  assert.ok(lifecycle.roles.includes('lifecycle-owner-language'));
  assert.ok(lifecycle.roles.includes('reconciler-language'));
  assert.ok(lifecycle.roles.includes('absence-convergence-language'));
});

test('fail-closed outcome precedence preserves opaque anchors', () => {
  assert.deepEqual(
    deriveOutcome({
      coverageComplete: false,
      unknowns: [{ code: 'accepted-source-anchor-opaque' }],
      eligibleChains: [],
    }),
    {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'accepted-source-anchor-opaque',
    }
  );
  assert.equal(
    deriveOutcome({
      coverageComplete: true,
      unknowns: [],
      eligibleChains: [],
    }).status,
    'refuted'
  );
  assert.equal(
    deriveOutcome({
      coverageComplete: true,
      unknowns: [],
      eligibleChains: [{}],
    }).status,
    'supported'
  );
  assert.equal(
    deriveOutcome({
      invalid: true,
      coverageComplete: true,
      unknowns: [],
      eligibleChains: [{}],
    }).status,
    'invalid'
  );
});

test('inventory source exposes no alternate process executable', () => {
  const source = readFileSync(new URL('./inventory-lib.mjs', import.meta.url), 'utf8');
  assert.equal(source.match(/\bspawn\(GIT_EXECUTABLE/gu)?.length, 1);
  assert.match(source, /const GIT_EXECUTABLE = '\/usr\/bin\/git'/u);
  assert.doesNotMatch(source, /execSync|execFileSync|fork\(|fetch\(/u);
});
