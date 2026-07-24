#!/usr/bin/env node

import { readJson, writeJson } from './lib/util.mjs';
import { verifyEvidence } from './verify-lib.mjs';

const [firstPath, secondPath, outputPath] = process.argv.slice(2);
if (!firstPath || !secondPath) {
  throw new Error(
    'Usage: node lab/h034/compare.mjs <first-run.json> <second-run.json> [output.json]'
  );
}
const firstVerification = await verifyEvidence(firstPath);
const secondVerification = await verifyEvidence(secondPath);
const first = await readJson(firstPath);
const second = await readJson(secondPath);
if (first.runId === second.runId)
  throw new Error('Reproduction runs must have distinct identities');
if (JSON.stringify(first.semanticAssertions) !== JSON.stringify(second.semanticAssertions)) {
  throw new Error('Clean-room runs produced different semantic assertions');
}
const comparison = {
  schemaVersion: 'overlaykit-h034-reproduction-comparison/v1',
  firstRunId: first.runId,
  secondRunId: second.runId,
  comparedAt: new Date().toISOString(),
  moduleArchivesMayDiffer: true,
  firstModuleArchiveSha256: first.moduleArchiveSha256,
  secondModuleArchiveSha256: second.moduleArchiveSha256,
  semanticAssertions: first.semanticAssertions,
  receiptCounts: [firstVerification.receiptCount, secondVerification.receiptCount],
  equivalent: true,
};
if (outputPath) await writeJson(outputPath, comparison);
process.stdout.write(`${JSON.stringify(comparison, null, 2)}\n`);
