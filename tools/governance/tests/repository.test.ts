import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../src/canonical.js';
import { compileGovernance } from '../src/compiler.js';
import { buildManifest } from '../src/manifest.js';
import {
  findRepoRoot,
  loadContract,
  readBaseChangeRecords,
  readBaseManifest,
  readStoredManifest,
  verifyMechanismBindings,
  verifyPinnedWorkflowActions,
} from '../src/repository.js';

describe('OverlayKit governance contract', () => {
  it('loads, binds to real mechanisms, and matches generated artifacts', () => {
    const root = findRepoRoot();
    const contract = loadContract(root);
    const headManifest = readBaseManifest(root, 'HEAD');

    verifyMechanismBindings(root, contract.mechanisms);
    verifyPinnedWorkflowActions(root);
    expect(headManifest).not.toBeNull();
    const headChangeStatuses = Object.fromEntries(
      readBaseChangeRecords(root, 'HEAD', headManifest!).map(({ change }) => [
        change.id,
        change.status,
      ])
    );
    expect(headChangeStatuses).toMatchObject({
      'CHG-0001': 'implemented',
      'CHG-0002': 'implemented',
    });
    expect(contract.changes.find(({ change }) => change.id === 'CHG-0005')?.change.status).toBe(
      'implemented'
    );
    expect(contract.changes.find(({ change }) => change.id === 'CHG-0013')).toEqual(
      expect.objectContaining({
        contentHash: '6e7050e85f5fa94c2677b1f1a6a400ca1ed0136fffd860c851d6aa8975514b87',
        change: expect.objectContaining({ status: 'proposed' }),
      })
    );
    expect(contract.changes.find(({ change }) => change.id === 'CHG-0014')?.change.status).toBe(
      'implemented'
    );
    expect(contract.changes.find(({ change }) => change.id === 'CHG-0015')).toEqual(
      expect.objectContaining({
        contentHash: 'b2cd667fad87b366163549cdb3b0ffaac95ffd591fc53d6158c229a516ae7e25',
        change: expect.objectContaining({ status: 'proposed' }),
      })
    );
    expect(contract.changes.find(({ change }) => change.id === 'CHG-0016')?.change.status).toBe(
      'implemented'
    );

    const plan = compileGovernance(contract);
    const manifest = buildManifest(contract, plan);
    expect(plan.profileVersion).toBe('1.6.0');
    expect(plan.decisions).toEqual([
      expect.objectContaining({
        id: 'ADR-0001',
        effectiveStatus: 'accepted',
        supersededBy: null,
      }),
      expect.objectContaining({
        id: 'ADR-0002',
        effectiveStatus: 'accepted',
        supersededBy: null,
      }),
      expect.objectContaining({
        id: 'ADR-0003',
        effectiveStatus: 'accepted',
        supersededBy: null,
      }),
      expect.objectContaining({
        id: 'ADR-0004',
        effectiveStatus: 'accepted',
        supersededBy: null,
      }),
      expect.objectContaining({
        id: 'ADR-0005',
        effectiveStatus: 'accepted',
        supersededBy: null,
      }),
      expect.objectContaining({
        id: 'ADR-0006',
        effectiveStatus: 'accepted',
        supersededBy: null,
      }),
    ]);
    expect(plan.rules.map(({ id }) => id)).toEqual(
      expect.arrayContaining([
        'surface-thread-replacement-claim-is-exactly-bounded',
        'experimental-worker-signal-is-not-production-policy',
        'physical-mechanism-evidence-does-not-expand-specifications',
        'production-recovery-requires-successor-slice',
      ])
    );
    expect(contract.profile.specificationIds).toEqual(['SPEC-0001', 'SPEC-0002']);
    expect(
      sha256(
        readFileSync(
          join(
            root,
            'evidence/h042/f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88/replay-15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36.tar.gz'
          )
        )
      )
    ).toBe('15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36');
    expect(
      sha256(
        readFileSync(
          join(
            root,
            'evidence/h043/64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8/replay-fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec.tar.gz'
          )
        )
      )
    ).toBe('fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec');
    expect(sha256(readFileSync(join(root, '.overlaykit/governance/plan.json')))).toBe(
      '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243'
    );
    expect(sha256(readFileSync(join(root, '.overlaykit/governance/profile.json')))).toBe(
      'e61fde755b80c66742df144d5e7bcb4309629542e3bdba666a347f65d3341787'
    );
    expect(plan.gates.find((gate) => gate.id === 'signed-identity')).toEqual(
      expect.objectContaining({
        tier: 'deferred',
        boundTo: 'github:signed-commits',
        sourceDecision: 'ADR-0001',
      })
    );
    expect(plan.gates.find((gate) => gate.id === 'independent-review')).toEqual(
      expect.objectContaining({
        tier: 'deferred',
        sourceDecision: 'ADR-0001',
      })
    );
    expect(plan.specifications).toEqual([
      expect.objectContaining({
        id: 'SPEC-0001',
        effectiveStatus: 'accepted',
        userStoryIds: ['US-001'],
      }),
      expect.objectContaining({
        id: 'SPEC-0002',
        effectiveStatus: 'accepted',
        userStoryIds: ['US-002'],
      }),
    ]);
    const storedPlan = JSON.parse(
      readFileSync(join(root, '.overlaykit/governance/plan.json'), 'utf8')
    ) as unknown;
    const storedManifest = JSON.parse(
      readFileSync(join(root, '.overlaykit/governance/manifest.json'), 'utf8')
    ) as unknown;

    expect(canonicalJson(storedPlan)).toBe(canonicalJson(plan));
    expect(canonicalJson(storedManifest)).toBe(canonicalJson(manifest));
  });

  it('fails closed when a base change blob is missing, mismatched, or changes identity', () => {
    const root = findRepoRoot();
    const fixture = mkdtempSync(join(tmpdir(), 'overlaykit-base-change-'));
    const governanceDirectory = join(fixture, '.overlaykit', 'governance');
    const changesDirectory = join(governanceDirectory, 'changes');
    const sourcePath = join(root, '.overlaykit', 'governance', 'changes', 'CHG-0001.json');
    const targetPath = join(changesDirectory, 'CHG-0001.json');

    try {
      mkdirSync(changesDirectory, { recursive: true });
      cpSync(
        join(root, '.overlaykit', 'governance', 'schemas'),
        join(governanceDirectory, 'schemas'),
        { recursive: true }
      );
      const raw = readFileSync(sourcePath, 'utf8');
      writeFileSync(targetPath, raw);
      execFileSync('git', ['init'], { cwd: fixture, stdio: 'ignore' });
      execFileSync('git', ['add', '.'], { cwd: fixture, stdio: 'ignore' });
      execFileSync(
        'git',
        [
          '-c',
          'user.name=OverlayKit Test',
          '-c',
          'user.email=test@overlaykit.invalid',
          '-c',
          'commit.gpgsign=false',
          'commit',
          '-m',
          'Base change fixture',
        ],
        { cwd: fixture, stdio: 'ignore' }
      );

      const storedManifest = readStoredManifest(root);
      const validManifest = {
        ...storedManifest,
        changes: { 'CHG-0001': sha256(raw) },
      };
      expect(
        readBaseChangeRecords(fixture, 'HEAD', validManifest).map(({ change }) => change.id)
      ).toEqual(['CHG-0001']);

      expect(() =>
        readBaseChangeRecords(fixture, 'HEAD', {
          ...validManifest,
          changes: { 'CHG-0001': 'f'.repeat(64) },
        })
      ).toThrowError(/does not match its manifest hash/);
      expect(() =>
        readBaseChangeRecords(fixture, 'HEAD', {
          ...validManifest,
          changes: { 'CHG-9999': 'f'.repeat(64) },
        })
      ).toThrowError(/references missing CHG-9999/);

      const changedIdentity = `${JSON.stringify(
        { ...JSON.parse(raw), id: 'CHG-0002' },
        null,
        2
      )}\n`;
      writeFileSync(targetPath, changedIdentity);
      execFileSync('git', ['add', '.'], { cwd: fixture, stdio: 'ignore' });
      execFileSync(
        'git',
        [
          '-c',
          'user.name=OverlayKit Test',
          '-c',
          'user.email=test@overlaykit.invalid',
          '-c',
          'commit.gpgsign=false',
          'commit',
          '-m',
          'Change fixture identity',
        ],
        { cwd: fixture, stdio: 'ignore' }
      );
      expect(() =>
        readBaseChangeRecords(fixture, 'HEAD', {
          ...validManifest,
          changes: { 'CHG-0001': sha256(changedIdentity) },
        })
      ).toThrowError(/identity mismatch/);
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });
});
