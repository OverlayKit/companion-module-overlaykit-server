import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { H047_SUBJECT, canonicalJson } from './inventory-lib.mjs';
import { H047_SOURCE_PATHS, buildH047Bundle, createRepositoryReader } from './run.mjs';

const REQUIRE_ANCHOR = process.env.H047_REQUIRE_ANCHOR === '1';
const OID = '1'.repeat(40);

function successfulSpawn(invocations) {
  return (executable, args, options) => {
    invocations.push({ executable, args, options });
    return {
      error: undefined,
      status: 0,
      signal: null,
      stdout: Buffer.alloc(0),
      stderr: Buffer.alloc(0),
    };
  };
}

function anchorPrelude({
  commit = '1'.repeat(40),
  parent = H047_SUBJECT.commit,
  tree = '3'.repeat(40),
  subjectTree = H047_SUBJECT.tree,
} = {}) {
  return new Map([
    ['rev-parse HEAD^{commit}', Buffer.from(`${commit}\n`)],
    ['rev-parse HEAD^1', Buffer.from(`${parent}\n`)],
    ['rev-parse HEAD^{tree}', Buffer.from(`${tree}\n`)],
    [`rev-parse ${H047_SUBJECT.commit}^{tree}`, Buffer.from(`${subjectTree}\n`)],
  ]);
}

function commitObject(parentLines, message = 'H-047 source anchor') {
  return Buffer.from(
    [
      `tree ${'3'.repeat(40)}`,
      ...parentLines.map((parent) => `parent ${parent}`),
      'author H047 Test <h047@example.invalid> 0 +0000',
      'committer H047 Test <h047@example.invalid> 0 +0000',
      '',
      message,
      '',
    ].join('\n')
  );
}

test('freezes a sorted eleven-file harness closure separate from the subject', () => {
  assert.equal(H047_SOURCE_PATHS.length, 11);
  assert.deepEqual(H047_SOURCE_PATHS, [...H047_SOURCE_PATHS].sort());
  assert.equal(new Set(H047_SOURCE_PATHS).size, H047_SOURCE_PATHS.length);
  assert.ok(H047_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0022.json'));
  assert.ok(H047_SOURCE_PATHS.includes('lab/h047/run.mjs'));
  assert.ok(H047_SOURCE_PATHS.includes('lab/h047/review-map.json'));
  assert.ok(H047_SOURCE_PATHS.includes('lab/h047/verify.mjs'));
  assert.ok(H047_SOURCE_PATHS.every((entry) => !entry.startsWith('artifacts/')));
  assert.equal(
    H047_SOURCE_PATHS.some((entry) => entry.includes(H047_SUBJECT.commit)),
    false
  );
});

test('repository reader rejects every Git command outside its exact read-only allowlist', () => {
  let spawnCalled = false;
  const reader = createRepositoryReader({
    root: '/path-that-must-not-be-read',
    spawn() {
      spawnCalled = true;
      throw new Error('spawn must not be reached');
    },
  });
  for (const command of [
    null,
    'status',
    [],
    ['fetch'],
    ['checkout', 'main'],
    ['reset', '--hard'],
    ['clean', '-fd'],
    ['config', '--get', 'user.name'],
    ['cat-file', 'blob', 'not-an-oid'],
    ['cat-file', '-p', OID],
    ['cat-file', 'commit', OID, 'extra'],
    ['status', '--short'],
    ['status', '--porcelain=v1', '--untracked-files=all', '--ignored'],
    ['ls-tree', 'HEAD'],
    ['ls-tree', '-rz', '--full-tree', 'HEAD'],
    ['diff-tree', '--no-commit-id', '--name-only', '-r', '-z', '2'.repeat(40), OID],
    ['rev-parse', 'HEAD^2'],
    ['verify-commit', 'A'.repeat(40)],
  ]) {
    assert.throws(() => reader.git(command), /outside the H-047 allowlist/u);
  }
  assert.equal(spawnCalled, false);
  assert.deepEqual(reader.counts(), {});
});

test('repository reader admits only the exact commands with a zero-inheritance Git environment', () => {
  const invocations = [];
  const reader = createRepositoryReader({
    root: '/bounded/repository',
    spawn: successfulSpawn(invocations),
  });
  const allowed = [
    ['cat-file', 'blob', OID],
    ['cat-file', 'commit', OID],
    ['diff-tree', '--no-commit-id', '--name-only', '-r', '-z', H047_SUBJECT.commit, OID],
    ['ls-tree', '-rz', '--full-tree', OID],
    ['rev-parse', 'HEAD^{commit}'],
    ['rev-parse', 'HEAD^1'],
    ['rev-parse', 'HEAD^{tree}'],
    ['rev-parse', `${H047_SUBJECT.commit}^{tree}`],
    ['status', '--porcelain=v1', '--untracked-files=all'],
    ['verify-commit', OID],
  ];
  for (const command of allowed) reader.git(command);

  assert.deepEqual(
    invocations.map(({ executable, args }) => ({ executable, args })),
    allowed.map((args) => ({ executable: '/usr/bin/git', args }))
  );
  assert.deepEqual(reader.counts(), {
    'cat-file-blob': 1,
    'cat-file-commit': 1,
    'diff-tree': 1,
    'ls-tree': 1,
    'rev-parse': 4,
    status: 1,
    'verify-commit': 1,
  });
  for (const { options } of invocations) {
    assert.equal(options.cwd, '/bounded/repository');
    assert.deepEqual(options.env, {
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
    });
    assert.equal(Object.hasOwn(options.env, 'HOME'), false);
  }
});

test('producer source exposes no live-observation or mutation process', async () => {
  const source = await readFile(fileURLToPath(new URL('./run.mjs', import.meta.url)), 'utf8');
  assert.match(source, /const GIT_EXECUTABLE = '\/usr\/bin\/git'/u);
  assert.match(source, /GIT_NO_LAZY_FETCH: '1'/u);
  assert.match(source, /GIT_OPTIONAL_LOCKS: '0'/u);
  assert.match(source, /reader\.git\(\['verify-commit', sourceAnchorCommit\]\)/u);
  assert.equal(source.match(/adrAssessment: H047_ADR_ASSESSMENT/gu)?.length, 2);
  assert.doesNotMatch(source, /(?:docker|lsusb|systemctl|udevadm|hidraw|kill)\s*\(/u);
  assert.doesNotMatch(source, /process\.env/u);
  assert.doesNotMatch(source, /https?:\/\//u);
});

test('producer fails before observation when the source anchor is not a direct child', () => {
  const replies = new Map([
    ['rev-parse HEAD^{commit}', Buffer.from(`${'1'.repeat(40)}\n`)],
    ['rev-parse HEAD^1', Buffer.from(`${'2'.repeat(40)}\n`)],
    ['rev-parse HEAD^{tree}', Buffer.from(`${'3'.repeat(40)}\n`)],
    [`rev-parse ${H047_SUBJECT.commit}^{tree}`, Buffer.from(`${H047_SUBJECT.tree}\n`)],
  ]);
  const calls = [];
  const reader = {
    git(args) {
      const key = args.join(' ');
      calls.push(key);
      assert.ok(replies.has(key), `unexpected Git call: ${key}`);
      return replies.get(key);
    },
    counts() {
      return {};
    },
  };
  assert.throws(() => buildH047Bundle({ reader }), /parent is not the subject/u);
  assert.deepEqual(calls, [
    'rev-parse HEAD^{commit}',
    'rev-parse HEAD^1',
    'rev-parse HEAD^{tree}',
    `rev-parse ${H047_SUBJECT.commit}^{tree}`,
  ]);
});

test('producer rejects a merge anchor before signature verification or repository inventory', () => {
  const commit = '1'.repeat(40);
  const replies = anchorPrelude({ commit });
  replies.set(`cat-file commit ${commit}`, commitObject([H047_SUBJECT.commit, '4'.repeat(40)]));
  const calls = [];
  const reader = {
    git(args) {
      const key = args.join(' ');
      calls.push(key);
      assert.ok(replies.has(key), `unexpected Git call: ${key}`);
      return replies.get(key);
    },
    counts() {
      return {};
    },
  };
  assert.throws(() => buildH047Bundle({ reader }), /exactly the subject as its only parent/u);
  assert.equal(calls.includes(`verify-commit ${commit}`), false);
  assert.equal(
    calls.some((entry) => entry.startsWith('status ')),
    false
  );
});

test('producer counts parents only in commit headers and requires verify-commit success', () => {
  const commit = '1'.repeat(40);
  const replies = anchorPrelude({ commit });
  replies.set(
    `cat-file commit ${commit}`,
    commitObject(
      [H047_SUBJECT.commit],
      `message body\nparent ${'4'.repeat(40)}\nmust not become a commit parent`
    )
  );
  const calls = [];
  const reader = {
    git(args) {
      const key = args.join(' ');
      calls.push(key);
      if (key === `verify-commit ${commit}`) throw new Error('invalid source-anchor signature');
      assert.ok(replies.has(key), `unexpected Git call: ${key}`);
      return replies.get(key);
    },
    counts() {
      return {};
    },
  };
  assert.throws(() => buildH047Bundle({ reader }), /invalid source-anchor signature/u);
  assert.equal(calls.at(-1), `verify-commit ${commit}`);
  assert.equal(
    calls.some((entry) => entry.startsWith('status ')),
    false
  );
});

test('canonical comparison used by the producer is order-stable', () => {
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
});

let anchorBundle = null;
let anchorError = null;
try {
  anchorBundle = buildH047Bundle();
} catch (error) {
  anchorError = error;
}

test(
  'canonical producer admits the signed direct-child eleven-source anchor',
  {
    skip:
      !REQUIRE_ANCHOR && anchorBundle === null
        ? `source anchor not frozen yet: ${anchorError?.message ?? 'unknown reason'}`
        : false,
  },
  () => {
    assert.ifError(anchorError);
    assert.ok(anchorBundle);
    assert.equal(anchorBundle.run.sourceAnchor.parent, H047_SUBJECT.commit);
    assert.equal(anchorBundle.run.sourceAnchor.parentCount, 1);
    assert.equal(anchorBundle.run.sourceAnchor.signatureVerified, true);
    assert.deepEqual(anchorBundle.run.sourceAnchor.deltaPaths, H047_SOURCE_PATHS);
    assert.deepEqual(
      anchorBundle.run.sourceAnchor.sources.map(({ path }) => path),
      H047_SOURCE_PATHS
    );
    assert.equal(anchorBundle.run.capabilityAudit.gitNoLazyFetch, true);
    assert.equal(anchorBundle.run.capabilityAudit.gitOptionalLocks, false);
    assert.equal(anchorBundle.run.capabilityAudit.sourceAnchorSignatureVerified, true);
    assert.equal(anchorBundle.run.capabilityAudit.sourceAnchorParentCount, 1);
    assert.deepEqual(anchorBundle.run.outcome, {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'incomplete-ambiguous-or-unknown-coverage',
    });
    assert.equal(anchorBundle.run.summary.candidates, 101);
    assert.equal(anchorBundle.run.summary.unknowns, 7);
    assert.equal(anchorBundle.run.summary.eligibleChains, 0);
    assert.equal(anchorBundle.run.summary.coverageComplete, false);
    assert.equal(anchorBundle.candidateIndex.semanticReview.coverageComplete, true);
    assert.deepEqual(anchorBundle.run.adrAssessment, {
      status: 'no-decision-candidate-activated',
      rationaleCode: 'repository-inventory-selects-no-new-architecture',
      futureDecisionQuestion:
        'which accepted source of truth, lifecycle-owner role, reconciler, and convergence policy should govern a persistent Companion deployment if one is desired',
      authority: 'none',
      action: null,
    });
    assert.deepEqual(anchorBundle.candidateIndex.adrAssessment, anchorBundle.run.adrAssessment);
  }
);
