import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalHash, sha256 } from '../../tools/governance/src/canonical.ts';
import { H053_EVIDENCE_PATHS, buildH053Evidence, encodeH053Evidence } from './evidence-lib.mjs';
import { verifyH053EvidenceStructure } from './verify.mjs';

function assertion(condition, message) {
  if (!condition) {
    throw new Error(`H053_WRITE_REFUSED: ${message}`);
  }
}

function semanticBody(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  return body;
}

export function validateH053RunIdentity(run) {
  assertion(
    run !== null && typeof run === 'object' && !Array.isArray(run),
    'run must be an object'
  );
  assertion(
    typeof run.semanticSha256 === 'string' && /^[0-9a-f]{64}$/u.test(run.semanticSha256),
    'semantic SHA-256 is malformed'
  );
  const recomputed = canonicalHash(semanticBody(run));
  assertion(recomputed === run.semanticSha256, 'semantic SHA-256 does not match run content');
  assertion(
    run.runId === `h053-${recomputed.slice(0, 24)}`,
    'run id does not match semantic SHA-256'
  );
  assertion(
    run.schemaVersion === 'overlaykit-h053-additive-admission-run/v1' &&
      run.hypothesis === 'H-053' &&
      run.normative === false,
    'run is not a non-normative H-053 evidence envelope'
  );
  assertion(
    run.authority === 'none' &&
      run.action === null &&
      run.experiment?.outcome?.authority === 'none' &&
      run.experiment?.outcome?.action === null,
    'run creates authority or action'
  );
  assertion(
    ['supported', 'refuted', 'inconclusive', 'invalid'].includes(
      run.interpretation?.outcome?.status
    ) &&
      run.interpretation.outcome.status === run.experiment.outcome.status &&
      run.interpretation.outcome.reasonCode === run.experiment.outcome.reason,
    'run outcome is missing or internally inconsistent'
  );
  assertion(
    run.interpretation?.humanReview?.required === true &&
      run.interpretation.humanReview.accepted === null,
    'run claims self-approval or omits human review'
  );
  assertion(
    run.interpretation?.adrAssessment?.candidateActivated === false &&
      run.interpretation.adrAssessment.candidateRecordCreated === false,
    'run creates or activates an ADR'
  );
  assertion(
    run.experiment?.fixture?.nonNormative === true &&
      run.experiment.fixture.persisted === false &&
      run.realManifestTransition?.additionOnly === true,
    'run records unauthorized persistence or a non-additive real transition'
  );
  const prohibitedCapabilityFields = [
    'fixtureWritesOutsideLab',
    'networkActivity',
    'liveObservation',
    'usbOrHidrawActivity',
    'dockerActivity',
    'signalsOrServicesActivity',
    'realSpecificationMutation',
    'profileSchemaCompilerPlanOrProductMutation',
    'adrCreated',
    'gitIndexOrHistoryMutation',
    'publication',
  ];
  assertion(
    prohibitedCapabilityFields.every((field) => run.capabilityAudit?.observed?.[field] === false),
    'run records an unauthorized capability, mutation, or publication'
  );
  verifyH053EvidenceStructure(run);
  return recomputed;
}

function containedRelative(parent, target) {
  const relative = path.relative(parent, target);
  assertion(
    relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    `path escapes fixed evidence root: ${target}`
  );
  return relative;
}

function assertNoSymlinkAncestors(root, target) {
  const absoluteRoot = path.resolve(root);
  const absoluteTarget = path.resolve(target);
  const relative = containedRelative(absoluteRoot, absoluteTarget);
  let current = absoluteRoot;
  const components = relative.split(path.sep);
  for (const [index, component] of components.entries()) {
    current = path.join(current, component);
    const metadata = lstatSync(current);
    assertion(!metadata.isSymbolicLink(), `symlink path component ${current}`);
    if (index < components.length - 1) {
      assertion(metadata.isDirectory(), `non-directory path ancestor ${current}`);
    }
  }
}

function assertRealContainment(parent, target) {
  const realParent = realpathSync(parent);
  const realTarget = realpathSync(target);
  containedRelative(realParent, realTarget);
  return { realParent, realTarget };
}

function assertDirectory(directory, expectedMode = null, containmentRoot = null) {
  const metadata = lstatSync(directory);
  assertion(metadata.isDirectory() && !metadata.isSymbolicLink(), `unsafe directory ${directory}`);
  if (containmentRoot !== null) {
    assertNoSymlinkAncestors(containmentRoot, directory);
    assertRealContainment(containmentRoot, directory);
  }
  if (expectedMode !== null) {
    const mode = metadata.mode & 0o777;
    assertion(mode === expectedMode, `directory mode drift at ${directory}`);
  }
}

function createFixedDirectory(directory, expectedMode, allowExisting, containmentRoot) {
  try {
    mkdirSync(directory, { mode: expectedMode });
  } catch (error) {
    if (!(allowExisting && error?.code === 'EEXIST')) {
      throw error;
    }
  }
  assertDirectory(directory, expectedMode, containmentRoot);
}

function inspectEvidenceFile(filePath, evidenceRoot) {
  assertNoSymlinkAncestors(evidenceRoot, filePath);
  const { realParent, realTarget } = assertRealContainment(evidenceRoot, filePath);
  containedRelative(realParent, realTarget);
  const descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(descriptor);
    const pathnameMetadata = lstatSync(filePath);
    assertion(
      metadata.isFile() &&
        pathnameMetadata.isFile() &&
        !pathnameMetadata.isSymbolicLink() &&
        metadata.nlink === 1 &&
        pathnameMetadata.nlink === 1 &&
        metadata.dev === pathnameMetadata.dev &&
        metadata.ino === pathnameMetadata.ino,
      `unsafe evidence file ${filePath}`
    );
    assertion((metadata.mode & 0o777) === 0o600, `evidence mode drift at ${filePath}`);
    return { bytes: readFileSync(descriptor), metadata };
  } finally {
    closeSync(descriptor);
  }
}

function writeExclusiveOrVerify(filePath, bytes, evidenceRoot) {
  let reused = false;
  try {
    writeFileSync(filePath, bytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error?.code !== 'EEXIST') {
      throw error;
    }
    reused = true;
    assertion(
      inspectEvidenceFile(filePath, evidenceRoot).bytes.equals(bytes),
      `existing evidence differs at ${filePath}`
    );
  }
  inspectEvidenceFile(filePath, evidenceRoot);
  return reused;
}

export function preserveH053Evidence(run = buildH053Evidence()) {
  const semanticSha256 = validateH053RunIdentity(run);
  const bytes = encodeH053Evidence(run);
  const repositoryRoot = realpathSync(H053_EVIDENCE_PATHS.repositoryRoot);
  const artifactsRoot = path.join(repositoryRoot, 'artifacts');
  assertDirectory(artifactsRoot, null, repositoryRoot);
  const h053Root = path.join(artifactsRoot, 'h053');
  const runsRoot = path.join(h053Root, 'runs');
  createFixedDirectory(h053Root, 0o700, true, repositoryRoot);
  createFixedDirectory(runsRoot, 0o700, true, repositoryRoot);
  const runDirectory = path.join(runsRoot, semanticSha256);
  containedRelative(runsRoot, runDirectory);
  createFixedDirectory(runDirectory, 0o700, true, repositoryRoot);
  const runPath = path.join(runDirectory, 'run.json');
  containedRelative(runsRoot, runPath);
  const reused = writeExclusiveOrVerify(runPath, bytes, runsRoot);
  return {
    runId: run.runId,
    semanticSha256,
    rawSha256: sha256(bytes),
    byteLength: bytes.length,
    path: path.relative(repositoryRoot, runPath),
    reused,
    authority: 'none',
    action: null,
  };
}

function main() {
  const args = process.argv.slice(2);
  assertion(
    args.length === 0 || (args.length === 1 && args[0] === '--write'),
    'usage: node --import tsx lab/h053/run.mjs [--write]'
  );
  const run = buildH053Evidence();
  if (args[0] === '--write') {
    process.stdout.write(`${JSON.stringify(preserveH053Evidence(run))}\n`);
    return;
  }
  process.stdout.write(encodeH053Evidence(run));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
