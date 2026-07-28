import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
  H048_ARTIFACT_ROOT,
  H048_SOURCE_PATHS,
  buildH048Bundle,
  readLocalSourceClosure,
  validateSubjectLock,
  writeBundle,
} from './run.mjs';

const EXPECTED_CLAIM_BOUNDARY = {
  includes: [
    'the exact two nominated Git main trees',
    'tracked archive members reachable from those trees',
    'explicit repository-local and cross-repository indirections admitted by the review map',
    'the accepted repo-set and ref-set anchors only when their exact preimages are available',
  ],
  excludes: [
    'inaccessible organization variables and secrets',
    'unreported or inaccessible private sources',
    'wikis, issues, projects, deleted refs, runbooks, and CMDB',
    'host configuration, current host state, live observation, intent, compliance, drift, cause, and remedy',
    'actual external operational ownership',
    'installation, configuration, start, stop, restart, signaling, reconciliation, publication, ADR, SPEC, and production policy',
  ],
  authority: 'none',
  action: null,
};
const EXPECTED_CLAIM_BOUNDARY_SHA256 =
  '3493ff642bc71755e0e2f4c492c552267ec15efd7500b473b477c11e00058224';
const EXPECTED_PREDICATES = [
  'effectiveAcceptedProductionAuthority',
  'exactImageReferenceAndId',
  'spec0001LinuxHostBinding',
  'deploymentPresenceAndCardinality',
  'repositoryDeclaredLifecycleOwner',
  'reconcilerMechanism',
  'absenceToConvergenceRule',
  'explicitLinkClosure',
];

test('freezes the exact sorted local unsigned H-048 source closure', () => {
  assert.equal(H048_SOURCE_PATHS.length, 14);
  assert.deepEqual(H048_SOURCE_PATHS, [...H048_SOURCE_PATHS].sort());
  assert.equal(new Set(H048_SOURCE_PATHS).size, H048_SOURCE_PATHS.length);
  for (const required of [
    '.gitignore',
    '.overlaykit/governance/changes/CHG-0024.json',
    '.overlaykit/governance/manifest.json',
    'lab/h048/archive-lib.mjs',
    'lab/h048/subject-lock.json',
    'lab/h048/review-map.json',
    'lab/h048/run.mjs',
    'lab/h048/verify.mjs',
  ]) {
    assert.ok(H048_SOURCE_PATHS.includes(required), `missing source ${required}`);
  }
  assert.equal(
    H048_SOURCE_PATHS.some((entry) => entry.startsWith('artifacts/')),
    false
  );
});

test('local source closure is explicit about absent signature and binds every byte', () => {
  const closure = readLocalSourceClosure();
  assert.equal(closure.document.admission.kind, 'local-content-addressed-unsigned');
  assert.equal(closure.document.admission.signatureStatus, 'absent-not-authorized');
  assert.equal(closure.document.admission.commit, null);
  assert.equal(closure.document.sourceCount, 14);
  assert.equal(closure.document.sources.length, 14);
  assert.match(closure.document.sourceSetSha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(
    closure.document.sources.map(({ path: sourcePath }) => sourcePath),
    H048_SOURCE_PATHS
  );
  for (const source of closure.document.sources) {
    assert.equal(source.repository, 'h048-local-unsigned-source-closure');
    assert.equal(source.blobFile, `sources/${source.sha256}.bin`);
    assert.ok(closure.blobs.get(source.sha256).length === source.byteLength);
  }
});

test('producer rejects source drift between module load, preflight, and postflight', () => {
  const stable = readLocalSourceClosure();
  const changed = {
    document: structuredClone(stable.document),
    blobs: new Map(stable.blobs),
  };
  changed.document.sourceSetSha256 = 'a'.repeat(64);

  assert.throws(
    () => buildH048Bundle({ sourceClosureReader: () => changed }),
    /pre-execution source closure differs from module-load bytes/u
  );

  let reads = 0;
  assert.throws(
    () =>
      buildH048Bundle({
        sourceClosureReader: () => {
          reads += 1;
          return reads === 1 ? stable : changed;
        },
      }),
    /source closure changed during producer execution/u
  );
  assert.equal(reads, 2);
});

test('imported producer rejects a non-pinned Node runtime before evidence construction', () => {
  const systemVersion = spawnSync('/usr/bin/node', ['--version'], {
    encoding: 'utf8',
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
  });
  assert.equal(systemVersion.status, 0);
  if (systemVersion.stdout.trim() === 'v22.20.0') return;
  const hostile = spawnSync(
    '/usr/bin/node',
    [
      '--input-type=module',
      '--eval',
      "import { buildH048Bundle } from './lab/h048/run.mjs'; buildH048Bundle();",
    ],
    {
      cwd: path.resolve(new URL('../..', import.meta.url).pathname),
      encoding: 'utf8',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
    }
  );
  assert.notEqual(hostile.status, 0);
  assert.match(hostile.stderr, /requires exact Node 22\.20\.0/u);
});

test('subject lock rejects extra keys and changes to target, policy, or anchor metadata', () => {
  const subjectLock = JSON.parse(
    readFileSync(new URL('./subject-lock.json', import.meta.url), 'utf8')
  );
  validateSubjectLock(subjectLock);
  for (const mutate of [
    (value) => {
      value.extra = true;
    },
    (value) => {
      value.repoSet.extra = true;
    },
    (value) => {
      value.repositories[0].localLocator = '../overlaykit';
    },
    (value) => {
      value.repositories[1].refSet.extra = true;
    },
    (value) => {
      value.target.imageInterpretation = 'production-policy';
    },
    (value) => {
      value.predicateOrder.reverse();
    },
    (value) => {
      value.outcomePolicy.refuted = 'zero chains even with unknowns';
    },
    (value) => {
      value.claimBoundary.extra = true;
    },
  ]) {
    const hostile = structuredClone(subjectLock);
    mutate(hostile);
    assert.throws(() => validateSubjectLock(hostile));
  }
});

test('real producer closes both main trees and fails closed on opaque accepted sets', () => {
  const bundle = buildH048Bundle();
  for (const artifact of [bundle.sourceMap, bundle.candidateIndex, bundle.run]) {
    assert.deepEqual(artifact.claimBoundary, EXPECTED_CLAIM_BOUNDARY);
    assert.equal(artifact.claimBoundaryCanonicalSha256, EXPECTED_CLAIM_BOUNDARY_SHA256);
  }
  assert.equal(bundle.sourceMap.repositories.length, 2);
  assert.equal(bundle.sourceMap.entryCount, 679);
  assert.equal(bundle.sourceMap.archives.roots.length, 3);
  assert.equal(bundle.sourceMap.archives.observations.archives, 4);
  assert.equal(bundle.sourceMap.archives.observations.regularMembers, 225);
  assert.deepEqual(bundle.run.summary, {
    repositories: 2,
    mainTreeEntries: 679,
    trackedArchiveRoots: 3,
    expandedArchiveOccurrences: 4,
    expandedArchiveMembers: 225,
    candidates: 599,
    indirections: 1508,
    unresolvedIndirections: 83,
    unknowns: 6,
    eligibleChains: 0,
    missingPredicates: EXPECTED_PREDICATES,
    coverageComplete: false,
  });

  const indirectionsByStatus = Object.groupBy(
    bundle.candidateIndex.indirections,
    (indirection) => indirection.status
  );
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(indirectionsByStatus).map(([status, indirections]) => [
        status,
        indirections.length,
      ])
    ),
    {
      'unversioned-subject-reference': 78,
      'excluded-outside-nominated-boundary': 1416,
      'unscoped-commit-reference': 5,
      'excluded-github-surface': 6,
      'resolved-exact-subject': 3,
    }
  );
  const exactSubjectCommits = new Map([
    ['OverlayKit/companion-module-overlaykit-server', '2d46d1c60e7aced224b47a8857d93015c5fb5c91'],
    ['OverlayKit/overlaykit', '9a5585de196ff972993c7ff81bf9c1461c47eaae'],
  ]);
  for (const indirection of indirectionsByStatus['resolved-exact-subject']) {
    assert.equal(indirection.targetCommit, exactSubjectCommits.get(indirection.targetRepository));
  }
  for (const indirection of indirectionsByStatus['excluded-outside-nominated-boundary']) {
    assert.equal(indirection.targetRepository, null);
    assert.equal(indirection.targetCommit, null);
  }
  for (const indirection of indirectionsByStatus['unversioned-subject-reference']) {
    assert.notEqual(indirection.targetRepository, null);
    assert.equal(indirection.targetCommit, null);
  }
  assert.equal(
    bundle.candidateIndex.indirections.some((indirection) =>
      ['resolved-subject-repository', 'opaque-external'].includes(indirection.status)
    ),
    false
  );
  assert.deepEqual(bundle.candidateIndex.chainAssessments, []);
  assert.deepEqual(bundle.candidateIndex.missingPredicates, EXPECTED_PREDICATES);
  assert.equal(bundle.candidateIndex.eligibleChains.length, 0);
  assert.equal(bundle.candidateIndex.coverageComplete, false);
  assert.deepEqual(bundle.candidateIndex.outcome, {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'accepted-source-anchor-opaque',
  });
  assert.equal(
    bundle.candidateIndex.unknowns.filter(
      (unknown) => unknown.code === 'accepted-source-anchor-opaque'
    ).length,
    3
  );
  assert.equal(bundle.run.authority, 'none');
  assert.equal(bundle.run.action, null);
  assert.equal(bundle.run.capabilityAudit.networkObserved, false);
  assert.equal(bundle.run.capabilityAudit.nodeVersion, '22.20.0');
  assert.equal(bundle.run.capabilityAudit.productionMutationObserved, false);
});

test('writer creates an exclusive 0700/0600 ignored evidence boundary', () => {
  const runId = `h048-writer-${process.pid}`;
  const expectedOutput = path.join(H048_ARTIFACT_ROOT, runId);
  assert.equal(existsSync(expectedOutput), false);
  try {
    const bundle = buildH048Bundle();
    const output = writeBundle(runId, bundle);
    assert.equal(output, expectedOutput);
    assert.equal(lstatSync(output).mode & 0o777, 0o700);
    assert.equal(lstatSync(path.join(output, 'sources')).mode & 0o777, 0o700);
    assert.deepEqual(readdirSync(output).sort(), [
      'candidate-index.json',
      'review-universe.json',
      'run.json',
      'source-closure.json',
      'source-map.json',
      'sources',
    ]);
    for (const name of [
      'candidate-index.json',
      'review-universe.json',
      'run.json',
      'source-closure.json',
      'source-map.json',
    ]) {
      assert.equal(lstatSync(path.join(output, name)).mode & 0o777, 0o600);
    }
    for (const name of readdirSync(path.join(output, 'sources'))) {
      assert.match(name, /^[0-9a-f]{64}\.bin$/u);
      assert.equal(lstatSync(path.join(output, 'sources', name)).mode & 0o777, 0o600);
    }
    assert.throws(() => writeBundle(runId, bundle));
  } finally {
    rmSync(expectedOutput, { recursive: true, force: true });
  }
});

test('producer source exposes no network or live-observation child process', () => {
  const source = readFileSync(new URL('./run.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env/u);
  assert.doesNotMatch(source, /artifactRoot/u);
  assert.doesNotMatch(source, /spawnSync|execSync|execFileSync|fork\(/u);
  assert.doesNotMatch(source, /https?:\/\//u);
  assert.doesNotMatch(source, /(?:docker|lsusb|systemctl|udevadm|hidraw|kill)\s*\(/u);
});
