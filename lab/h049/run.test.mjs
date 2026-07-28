import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  H049_CHECK_IGNORE_ARGS,
  H049_REPOSITORY_ROOT,
  H049_SOURCE_PATHS,
  admitH049SubjectLockBytes,
  buildH049Bundle,
  createH049GitReader,
  parseH049Cli,
  validateH049IgnoreProbe,
} from './run.mjs';

describe('H-049 run boundary', () => {
  test('accepts only a fixed ignored output shape', () => {
    assert.deepEqual(parseH049Cli(['--out', 'artifacts/h049/canonical-a']), {
      output: 'artifacts/h049/canonical-a',
    });
    for (const argumentsList of [
      [],
      ['--out'],
      ['--out', '/tmp/h049'],
      ['--out', 'artifacts/h049/../escape'],
      ['--out', 'artifacts/h048/wrong'],
      ['--out', 'artifacts/h049/a', '--extra'],
    ]) {
      assert.throws(() => parseH049Cli(argumentsList), /usage|outside/u);
    }
  });

  test('source closure is exact and sorted', () => {
    assert.equal(H049_SOURCE_PATHS.length, 13);
    assert.deepEqual(H049_SOURCE_PATHS, [...H049_SOURCE_PATHS].sort());
    assert.equal(new Set(H049_SOURCE_PATHS).size, 13);
    assert.ok(H049_SOURCE_PATHS.includes('.gitignore'));
    assert.ok(H049_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0026.json'));
    assert.ok(H049_SOURCE_PATHS.includes('lab/h049/verify.mjs'));
  });

  test('admits only the exact byte-bound subject lock before Git is available', () => {
    const bytes = readFileSync(new URL('./subject-lock.json', import.meta.url));
    const admitted = admitH049SubjectLockBytes(bytes);
    assert.equal(admitted.subject.commit, '226d299a9b0d8acd592675f514a67d6229d0134a');
    const mutated = Buffer.from(bytes);
    mutated[mutated.length - 2] ^= 1;
    assert.throws(
      () => admitH049SubjectLockBytes(mutated),
      /subject lock bytes are not exactly admitted/u
    );
  });

  test('Git reader seals root and authority before any spawn', () => {
    let spawnCalls = 0;
    const spawn = () => {
      spawnCalls += 1;
      throw new Error('spawn must not be reached');
    };
    assert.throws(() => createH049GitReader({ root: '/tmp', spawn }), /sealed interface/u);
    assert.throws(() => createH049GitReader({ subjectLock: {}, spawn }), /sealed interface/u);
    assert.equal(spawnCalls, 0);
  });

  test('Git reader rejects commands outside the sealed four-command policy', () => {
    const reader = createH049GitReader({
      spawn: () => {
        throw new Error('spawn must not be reached');
      },
    });
    assert.throws(() => reader.git(['status', '--porcelain']), /outside the H-049 allowlist/u);
    assert.throws(
      () => reader.git(['cat-file', 'blob', '0'.repeat(40)]),
      /outside the H-049 allowlist/u
    );
  });

  test('Git reader uses the fixed root and zero-inheritance Git environment', () => {
    let invocation;
    const reader = createH049GitReader({
      spawn: (executable, args, options) => {
        invocation = { executable, args, options };
        return {
          error: undefined,
          status: 0,
          signal: null,
          stdout: Buffer.from(
            '.gitignore:5:artifacts/\tartifacts/h049/__h049-ignore-probe__\n',
            'utf8'
          ),
          stderr: Buffer.alloc(0),
        };
      },
    });
    const output = reader.git([...H049_CHECK_IGNORE_ARGS]);
    validateH049IgnoreProbe(output);
    assert.equal(invocation.executable, '/usr/bin/git');
    assert.deepEqual(invocation.args, H049_CHECK_IGNORE_ARGS);
    assert.equal(invocation.options.cwd, H049_REPOSITORY_ROOT);
    assert.deepEqual(invocation.options.env, {
      GIT_ALTERNATE_OBJECT_DIRECTORIES: '',
      GIT_ATTR_NOSYSTEM: '1',
      GIT_CONFIG_COUNT: '0',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_NO_LAZY_FETCH: '1',
      GIT_NO_REPLACE_OBJECTS: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
      LANG: 'C',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    });
    assert.equal(Object.hasOwn(invocation.options.env, 'HOME'), false);
  });

  test('ignore admission rejects unmatched, negated, broad, or multi-line receipts', () => {
    validateH049IgnoreProbe(
      Buffer.from('.gitignore:5:artifacts/\tartifacts/h049/__h049-ignore-probe__\n')
    );
    for (const output of [
      '',
      '.gitignore:5:artifacts/\tartifacts/h049/wrong\n',
      '.gitignore:6:!artifacts/h049/\tartifacts/h049/__h049-ignore-probe__\n',
      '.gitignore:5:*\tartifacts/h049/__h049-ignore-probe__\n',
      '.gitignore:5:artifacts/\tartifacts/h049/__h049-ignore-probe__\nextra\n',
    ]) {
      assert.throws(
        () => validateH049IgnoreProbe(Buffer.from(output)),
        /exact artifacts\/ ignore policy/u
      );
    }
  });

  test('builds deterministic bounded artifacts from Git blobs', () => {
    const first = buildH049Bundle();
    const second = buildH049Bundle();
    assert.deepEqual(first.bytes, second.bytes);
    assert.equal(first.documents.sourceMap.sourceCount, 9);
    assert.equal(first.documents.clauseUniverse.clauseCount, 901);
    assert.equal(first.documents.candidateIndex.candidates.length, 5);
    assert.equal(first.documents.candidateIndex.eligibleChains.length, 0);
    assert.equal(first.documents.run.summary.pendingHumanJudgments, 9);
    assert.equal(first.documents.run.outcome.status, 'inconclusive');
    assert.equal(first.documents.run.authority, 'none');
    assert.equal(first.documents.run.action, null);
    assert.deepEqual(first.documents.run.capabilityAudit.commandCounts, {
      'cat-file-blob': 9,
      'check-ignore': 1,
      'restricted-ls-tree': 1,
      'rev-parse': 2,
    });
    assert.equal(
      first.documents.run.capabilityAudit.sourceBinding,
      'on-disk-preflight-and-postflight-no-loader-attestation'
    );
    assert.equal(
      first.documents.run.capabilityAudit.fixedGitEnvironment.GIT_CONFIG_GLOBAL,
      '/dev/null'
    );
  });

  test('producer has no live, USB, Docker, or network imports', () => {
    const source = readFileSync(new URL('./run.mjs', import.meta.url), 'utf8');
    for (const forbidden of [
      'node:http',
      'node:https',
      'node:net',
      'node:dgram',
      'node:usb',
      '/dev/hidraw',
      '/var/run/docker.sock',
      'dockerode',
    ]) {
      assert.equal(source.includes(forbidden), false, forbidden);
    }
    assert.match(source, /O_NOFOLLOW/u);
    assert.match(source, /fstatSync/u);
    assert.match(source, /fchmodSync/u);
    assert.doesNotMatch(source, /\bchmodSync\(/u);
  });
});
