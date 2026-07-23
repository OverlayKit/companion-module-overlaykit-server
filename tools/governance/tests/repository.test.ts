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
      'CHG-0002': 'approved',
    });

    const plan = compileGovernance(contract);
    const manifest = buildManifest(contract, plan);
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
    ]);
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
