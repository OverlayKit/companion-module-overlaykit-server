#!/usr/bin/env node

import { verifyEvidence } from './verify-lib.mjs';

const runPath = process.argv[2];
if (!runPath) throw new Error('Usage: node lab/h034/verify.mjs <run.json>');
const result = await verifyEvidence(runPath);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
