import assert from 'node:assert/strict';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import {
  H047_EXPECTED_ACCEPTED_IDS,
  H047_EXPECTED_DEPLOYMENT_SURFACES,
  H047_EXPECTED_IDENTITY_COUNTS,
  H047_EXPECTED_IDENTITY_PATHS,
  H047_IMAGE,
  H047_PREDICATE_NAMES,
  H047_SIGNAL_POLICY,
  H047_SUBJECT,
  buildInventory,
  canonicalJson,
  candidateRole,
  classifyDeploymentPath,
  classifyTypedChains,
  deriveH047Outcome,
  expandTarGzipClosure,
  expandTarGzipForest,
  isEligibleChain,
  jsonPointer,
  parseLsTreeZ,
  readTarGzipMembers,
  scanSemanticSignals,
  semanticSignalRoles,
  sha256,
  sourceSetSha256,
} from './inventory-lib.mjs';

function treeRecord(path, oid = 'a'.repeat(40), mode = '100644', type = 'blob') {
  return Buffer.from(`${mode} ${type} ${oid}\t${path}\0`);
}

function writeTarString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  assert.ok(bytes.length <= length);
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  writeTarString(header, offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`);
}

function tarEntry(name, body = Buffer.alloc(0), type = '0', { linkName = '', mode = 0o644 } = {}) {
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
  writeTarString(header, 157, 100, linkName);
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

function mutateTarHeader(entry, mutate) {
  const result = Buffer.from(entry);
  const header = result.subarray(0, 512);
  mutate(header);
  header.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.fill(0, 148, 156);
  writeTarString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return result;
}

test('freezes the exact H-047 subject and reviewed sets', () => {
  assert.equal(H047_SUBJECT.commit, 'a68ab8f2c8a64828c1c685161ef9319bd8a837c7');
  assert.equal(H047_SUBJECT.entryCount, 238);
  assert.equal(H047_PREDICATE_NAMES.length, 8);
  assert.equal(H047_SIGNAL_POLICY.version, 'overlaykit-h047-semantic-signal-policy/v2');
  assert.equal(new Set(H047_PREDICATE_NAMES).size, 8);
  assert.equal(H047_EXPECTED_ACCEPTED_IDS.decisions.length, 6);
  assert.equal(H047_EXPECTED_ACCEPTED_IDS.specifications.length, 2);
  assert.equal(H047_EXPECTED_ACCEPTED_IDS.implementedChanges.length, 9);
  assert.equal(H047_EXPECTED_DEPLOYMENT_SURFACES.length, 8);
  assert.equal(H047_EXPECTED_IDENTITY_PATHS.length, 26);
  assert.deepEqual(H047_EXPECTED_IDENTITY_COUNTS, {
    referencePaths: 22,
    imageIdPaths: 25,
    bothPaths: 21,
    unionPaths: 26,
  });
});

test('canonical JSON, hashing, pointers, and source-set framing are deterministic', () => {
  assert.equal(canonicalJson({ z: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"z":1}');
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(jsonPointer({ 'a/b': { '~key': 7 } }, '/a~1b/~0key'), 7);
  assert.equal(jsonPointer({ a: 1 }, '/missing'), undefined);
  assert.throws(() => jsonPointer({}, '/bad~2escape'), /invalid JSON pointer escape/u);
  const entries = [
    { path: 'b', mode: '100644', byteLength: 1, sha256: 'b'.repeat(64) },
    { path: 'a', mode: '100755', byteLength: 2, sha256: 'a'.repeat(64) },
  ];
  assert.equal(sourceSetSha256(entries), sourceSetSha256([...entries].reverse()));
  assert.throws(() => sourceSetSha256([...entries, entries[0]]), /duplicate source-set path/u);
});

test('semantic signal scan is exact, case-insensitive, and binary-fail-closed', () => {
  assert.deepEqual(
    scanSemanticSignals(Buffer.from('Deploy lifecycle restartPolicy replicas:')).matches.map(
      ({ id }) => id
    ),
    ['deploy', 'lifecycle', 'restart-policy', 'restart-policy-camel', 'replicas-yaml']
  );
  assert.deepEqual(scanSemanticSignals(Buffer.from([0xff, 0xfe])), {
    utf8: false,
    matches: [],
  });
  assert.deepEqual(
    semanticSignalRoles(Buffer.from(`${H047_SUBJECT.commit} deploy lifecycle`), {
      acceptedGovernance: true,
    }),
    ['deployment', 'accepted-governance', 'lifecycle-wording']
  );
});

test('parses a NUL-framed ls-tree stream and rejects hostile structure', () => {
  const parsed = parseLsTreeZ(Buffer.concat([treeRecord('a'), treeRecord('b', 'b'.repeat(40))]));
  assert.deepEqual(parsed, [
    { mode: '100644', type: 'blob', oid: 'a'.repeat(40), path: 'a' },
    { mode: '100644', type: 'blob', oid: 'b'.repeat(40), path: 'b' },
  ]);
  assert.throws(() => parseLsTreeZ(Buffer.from('not-nul-terminated')), /NUL terminated/u);
  assert.throws(
    () => parseLsTreeZ(Buffer.concat([treeRecord('../escape')])),
    /unsafe repository path/u
  );
  assert.throws(
    () => parseLsTreeZ(Buffer.concat([treeRecord('dup'), treeRecord('dup', 'b'.repeat(40))])),
    /duplicate repository path/u
  );
  assert.throws(() => parseLsTreeZ(treeRecord('link', 'a'.repeat(40), '120000')), /unsupported/u);
  assert.throws(
    () => parseLsTreeZ(treeRecord('tree', 'a'.repeat(40), '040000', 'tree')),
    /unsupported ls-tree type/u
  );
  assert.throws(
    () => parseLsTreeZ(Buffer.concat([treeRecord('z'), treeRecord('a', 'b'.repeat(40))])),
    /not sorted/u
  );
});

test('parses archive members in-process and fails closed on unsafe archive structure', () => {
  const members = readTarGzipMembers(
    tarGzip([tarEntry('nested/one.txt', 'one'), tarEntry('two.json', '{"two":2}')])
  );
  assert.deepEqual([...members.keys()], ['nested/one.txt', 'two.json']);
  assert.equal(members.get('nested/one.txt').toString(), 'one');
  for (const path of ['../escape', '/absolute', './relative', 'nested//empty', 'C:drive']) {
    assert.throws(
      () => readTarGzipMembers(tarGzip([tarEntry(path, 'unsafe')])),
      /member path/u,
      path
    );
  }
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('duplicate', 'one'), tarEntry('duplicate', 'two')])),
    /duplicate member path/u
  );
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('link', '', '2')])),
    /strict profile rejects tar member type/u
  );
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('pax', 'metadata', 'x')])),
    /strict profile rejects tar member type/u
  );
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('directory///', '', '5')])),
    /strict profile rejects tar member type/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        tarGzip([tarEntry('regular', 'content', '0', { linkName: 'hidden-target' })])
      ),
    /carries a raw link name/u
  );
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('one', 'one')], Buffer.alloc(512))),
    /terminator is truncated/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(Buffer.concat([tarGzip([tarEntry('one', 'one')]), Buffer.alloc(1024)])),
    /trailing bytes/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        tarGzip([mutateTarHeader(tarEntry('legacy', 'one'), (header) => header.fill(0, 257, 265))])
      ),
    /unsupported tar magic\/version/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        tarGzip([
          mutateTarHeader(tarEntry('bad-version', 'one'), (header) =>
            writeTarString(header, 263, 2, '99')
          ),
        ])
      ),
    /unsupported tar magic\/version/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        tarGzip([
          mutateTarHeader(tarEntry('bad-size', 'one'), (header) =>
            writeTarString(header, 124, 12, '0000000001\0X')
          ),
        ])
      ),
    /non-octal byte|non-padding bytes/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        tarGzip([mutateTarHeader(tarEntry('empty-size'), (header) => header.fill(0x20, 124, 136))])
      ),
    /member size is empty/u
  );
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('bad-mode', 'one', '0', { mode: 0o777 })])),
    /unsupported mode/u
  );
  assert.throws(
    () => readTarGzipMembers(tarGzip([tarEntry('literal!/inside.txt', 'one')])),
    /reserved route delimiter/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(tarGzip([tarEntry('large', 'x'.repeat(2048))]), {
        maxDecompressedBytes: 1024,
      }),
    /gzip decoding failed/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(tarGzip([tarEntry('one'), tarEntry('two')]), {
        maxMembers: 1,
      }),
    /member count exceeds/u
  );
});

test('recursively closes nested archives under one global content-addressed budget', () => {
  const nested = tarGzip([tarEntry('inside.txt', 'nested')]);
  const root = tarGzip([tarEntry('plain.txt', 'plain'), tarEntry('nested/replay.tar.gz', nested)]);
  const doubleNested = tarGzip([tarEntry('deeper/replay.tar.gz', nested)]);
  const deepRoot = tarGzip([tarEntry('nested/replay.tar.gz', doubleNested)]);
  const closure = expandTarGzipClosure('evidence/root.tar.gz', root);
  assert.equal(closure.observations.archives, 2);
  assert.equal(closure.observations.regularMembers, 3);
  assert.deepEqual(
    closure.archives.map(({ virtualPath }) => virtualPath),
    ['evidence/root.tar.gz', 'evidence/root.tar.gz!/nested/replay.tar.gz']
  );
  assert.deepEqual(
    closure.members.map(({ virtualPath }) => virtualPath),
    [
      'evidence/root.tar.gz!/nested/replay.tar.gz',
      'evidence/root.tar.gz!/nested/replay.tar.gz!/inside.txt',
      'evidence/root.tar.gz!/plain.txt',
    ]
  );
  assert.match(closure.closureSha256, /^[0-9a-f]{64}$/u);
  assert.equal(closure.closureSha256, closure.expansion.closureSha256);
  assert.throws(
    () =>
      expandTarGzipClosure(
        'evidence/root.tar.gz',
        tarGzip([tarEntry('declared.tar.gz', 'not-gzip')])
      ),
    /extension\/signature mismatch/u
  );
  assert.throws(
    () =>
      expandTarGzipClosure('evidence/root.tar.gz', root, {
        maxArchives: 1,
      }),
    /archive count exceeds/u
  );
  assert.throws(
    () =>
      expandTarGzipClosure('evidence/root.tar.gz', deepRoot, {
        maxDepth: 1,
        maxArchives: 16,
      }),
    /nested archive depth exceeds/u
  );
});

test('shares one strict budget across the complete archive forest', () => {
  const first = tarGzip([tarEntry('first.txt', 'first')]);
  const second = tarGzip([tarEntry('second.txt', 'second')]);
  const executable = tarGzip([tarEntry('entrypoint.sh', '#!/bin/sh', '0', { mode: 0o755 })]);
  const forest = expandTarGzipForest([
    { path: 'evidence/first.tar.gz', bytes: first },
    { path: 'vendor/second.tgz', bytes: second },
  ]);
  assert.equal(forest.roots.length, 2);
  assert.equal(forest.observations.archives, 2);
  assert.equal(forest.observations.logicalMembers, 2);
  assert.equal(
    expandTarGzipClosure('evidence/executable.tar.gz', executable).expansion.members[0].mode,
    '100755'
  );
  assert.throws(
    () =>
      expandTarGzipForest(
        [
          { path: 'evidence/first.tar.gz', bytes: first },
          { path: 'vendor/second.tgz', bytes: second },
        ],
        { maxArchives: 1 }
      ),
    /archive count exceeds/u
  );
  assert.throws(
    () => expandTarGzipForest([{ path: 'evidence/first.tar.gz', bytes: first }], { typo: 1 }),
    /unknown archive limit/u
  );
  assert.throws(
    () => expandTarGzipForest([{ path: 'evidence/a!/first.tar.gz', bytes: first }]),
    /safe \.tar\.gz or \.tgz/u
  );
  for (const path of ['C:root.tar.gz', 'evidence/bad\nroot.tar.gz']) {
    assert.throws(() => expandTarGzipForest([{ path, bytes: first }]), /safe \.tar\.gz or \.tgz/u);
  }
});

test('recognizes exactly reviewed deployment shapes and fails closed on new formats', () => {
  for (const expected of H047_EXPECTED_DEPLOYMENT_SURFACES) {
    assert.deepEqual(classifyDeploymentPath(expected.path), {
      deploymentShaped: true,
      recognized: true,
      kind: expected.kind,
      disposition: expected.disposition,
    });
  }
  assert.deepEqual(classifyDeploymentPath('src/main.ts'), {
    deploymentShaped: false,
    recognized: true,
    kind: null,
    disposition: 'not-deployment-shaped',
  });
  assert.equal(classifyDeploymentPath('ops/companion.service').recognized, false);
  assert.equal(classifyDeploymentPath('deploy/companion.nomad').recognized, false);
  assert.equal(classifyDeploymentPath('k8s/companion.yaml').recognized, false);
  assert.equal(candidateRole('ops/companion.service'), 'unknown-deployment-surface');
});

test('keeps governance authority roles explicit', () => {
  const statuses = {
    '.overlaykit/governance/decisions/ADR-0006.json': { status: 'accepted' },
    '.overlaykit/governance/changes/CHG-0019.json': { status: 'proposed' },
  };
  assert.equal(
    candidateRole('.overlaykit/governance/decisions/ADR-0006.json', statuses),
    'accepted-decision'
  );
  assert.equal(
    candidateRole('.overlaykit/governance/changes/CHG-0019.json', statuses),
    'non-authoritative-proposal'
  );
  assert.equal(
    isEligibleChain(Object.fromEntries(H047_PREDICATE_NAMES.map((name) => [name, true]))),
    true
  );
  assert.throws(
    () =>
      isEligibleChain({
        ...Object.fromEntries(H047_PREDICATE_NAMES.map((name) => [name, true])),
        inferredAuthority: true,
      }),
    /exactly the eight predicates/u
  );
});

function typedEligible(prefix = 'one') {
  const deploymentKey = `deployment-${prefix}`;
  const authorityPath = `fixtures/${prefix}-authority.json`;
  const desiredPath = `fixtures/${prefix}-desired.json`;
  const atom = (kind, assertion, path = desiredPath) => ({
    id: `${prefix}-${kind}`,
    kind,
    subjectKey: `${prefix}-${kind}`,
    assertion: { deploymentKey, ...assertion },
    path,
  });
  return {
    atoms: [
      {
        id: `${prefix}-authority`,
        kind: 'effective-authority',
        subjectKey: `${prefix}-authority`,
        assertion: {},
        path: authorityPath,
      },
      {
        id: `${prefix}-host-role`,
        kind: 'host-role-definition',
        subjectKey: 'spec-0001-linux-production-host',
        assertion: {},
        path: authorityPath,
      },
      atom('production-scope', { scope: 'production' }),
      atom('image-ref', { imageReference: H047_IMAGE.reference }),
      atom('image-id', { imageId: H047_IMAGE.imageId }),
      atom('deployment-host-binding', { roleKey: 'spec-0001-linux-production-host' }),
      atom('desired-presence', { present: true }),
      atom('cardinality', { count: 1 }),
      atom('lifecycle-owner-role', { roleKey: 'fixture-owner' }),
      atom('reconciler', {
        controller: 'fixture-controller',
        trigger: 'fixture-trigger',
        target: 'fixture-target',
        action: 'fixture-action',
      }),
      atom('absence-condition', { condition: 'fixture-absent' }),
      atom('convergence-action', {
        action: 'fixture-create',
        postcondition: 'fixture-present',
      }),
    ],
    edges: [
      {
        kind: 'normative-requires',
        semanticRole: 'normative',
        sourcePath: authorityPath,
        targetPath: desiredPath,
      },
    ],
  };
}

test('reconstructs an abstract eligible chain only from typed atoms and normative reachability', () => {
  const fixture = typedEligible();
  const result = classifyTypedChains(fixture);
  assert.equal(result.components.length, 1);
  assert.equal(result.eligibleChains.length, 1);
  assert.equal(result.components[0].eligible, true);
  assert.equal(result.components[0].predicates.explicitLinkClosure, true);
  assert.equal(Object.values(result.components[0].predicates).every(Boolean), true);
});

test('typed chain classification fails closed on a missing link or mismatched host role', () => {
  const disconnected = typedEligible('disconnected');
  disconnected.edges = [];
  assert.equal(classifyTypedChains(disconnected).eligibleChains.length, 0);

  const wrongRole = typedEligible('wrong-role');
  wrongRole.atoms.find(({ kind }) => kind === 'deployment-host-binding').assertion.roleKey =
    'some-other-host';
  assert.equal(classifyTypedChains(wrongRole).eligibleChains.length, 0);
});

test('typed chain classification keeps multiple deployment keys separate', () => {
  const first = typedEligible('a');
  const second = typedEligible('b');
  const result = classifyTypedChains({
    atoms: [...first.atoms, ...second.atoms],
    edges: [...first.edges, ...second.edges],
  });
  assert.equal(result.eligibleChains.length, 2);
  assert.deepEqual(result.eligibleChains.map(({ deploymentKey }) => deploymentKey).sort(), [
    'deployment-a',
    'deployment-b',
  ]);
});

test('uses the exact three-way H-047 outcome semantics', () => {
  const eligible = [{ id: 'chain:fixture' }];
  assert.equal(
    deriveH047Outcome({
      coverageComplete: false,
      unknowns: [{ code: 'other-unknown' }],
      eligibleChains: eligible,
    }).status,
    'inconclusive'
  );
  assert.equal(
    deriveH047Outcome({ coverageComplete: true, unknowns: [], eligibleChains: eligible }).status,
    'supported'
  );
  assert.equal(
    deriveH047Outcome({ coverageComplete: true, unknowns: [], eligibleChains: [] }).status,
    'refuted'
  );
  for (const input of [
    { coverageComplete: false, unknowns: [], eligibleChains: [] },
    { coverageComplete: true, unknowns: [{ code: 'ambiguous' }], eligibleChains: [] },
  ]) {
    assert.equal(deriveH047Outcome(input).status, 'inconclusive');
  }
  assert.throws(
    () => deriveH047Outcome({ coverageComplete: true, unknowns: null, eligibleChains: [] }),
    /must be arrays/u
  );
});

test('buildInventory reports missing blobs and unexpected source closure as inconclusive', () => {
  const oid = 'a'.repeat(40);
  const result = buildInventory({
    treeBytes: treeRecord('README.md', oid),
    blobsByOid: new Map(),
    reviewMap: null,
  });
  assert.equal(result.coverageComplete, false);
  assert.equal(result.outcome.status, 'inconclusive');
  assert.equal(result.sourceMap.entries[0].available, false);
  assert.equal(result.sourceMap.sourceSetSha256, null);
  assert.ok(result.unknowns.some(({ code }) => code === 'blob-unavailable'));
  assert.ok(result.unknowns.some(({ code }) => code === 'ls-tree-stream-mismatch'));
  assert.ok(result.unknowns.some(({ code }) => code === 'entry-count-mismatch'));
});

test('buildInventory fails closed on an unknown deployment surface and malformed governance', () => {
  const firstOid = 'a'.repeat(40);
  const secondOid = 'b'.repeat(40);
  const treeBytes = Buffer.concat([
    treeRecord('.overlaykit/governance/decisions/ADR-0001.json', firstOid),
    treeRecord('ops/companion.service', secondOid),
  ]);
  const result = buildInventory({
    treeBytes,
    blobsByOid: new Map([
      [firstOid, Buffer.from('{"id":"ADR-9999","status":"accepted"}')],
      [secondOid, Buffer.from('[Service]\\nExecStart=/bin/false\\n')],
    ]),
    reviewMap: null,
  });
  assert.equal(result.outcome.status, 'inconclusive');
  assert.ok(result.unknowns.some(({ code }) => code === 'malformed-governance-record'));
  assert.ok(result.unknowns.some(({ code }) => code === 'unknown-deployment-surface'));
  assert.equal(result.surfaces[0].recognized, false);
});
