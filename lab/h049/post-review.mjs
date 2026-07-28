#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_PATH = fileURLToPath(import.meta.url);
const REPOSITORY_ROOT = path.resolve(path.dirname(MODULE_PATH), '../..');

export const H049 = Object.freeze({
  hypothesis: 'H-049',
  principal: '@rodrigoteamx',
  acceptedOn: '2026-07-27',
  subjectCommit: '226d299a9b0d8acd592675f514a67d6229d0134a',
  subjectTree: 'f0cd2b22b3c9da7b2c2d2cf5b93baa97dd1a5bcd',
  subjectSourceSetSha256: '3136aa776e1d15dcc2f3fc3597a6e7011f2b9601492936c5e1da65920a67e218',
  subjectRestrictedLsTreeSha256: 'e9e46d2e5affa66e72df0fbd1ed516c13327ebbb02d668ee92da2a4cd47b93c8',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  precontract: 'CHG-0026',
  precontractRawSha256: 'd336eadf0b99292e57745d6b58b61f9eab7b4074b7e3452758652c478eff6ebc',
  preReviewManifestRawSha256: 'f11ff1b0a2414acdf15a8814157e5a6de8b202e3b6d5653ca3e06a73753e218b',
  harnessSourceSetSha256: '2870263697a59dff253a578ec62cff5a72c5a4610eb21d8ff137e4b8c6e881b1',
  reviewMapRawSha256: '6b07f91932451ceacc9a28d28116404328f0fb4143160ff58a73c8dbf50d9782',
  reviewMapCanonicalSha256: '6e4c69836c57de051cd92826b5ac9103b7a9eeef2f1b0fb072f5df8f9c8db928',
  clauseUniverseSha256: '637671ba036157351305e3bf023645bcebb9f8ab0ec19d37e4988799754e7c79',
  candidateIndexSha256: '7c4e41bf052fc0f87fc3d1cd5370c3be6390fafac67ffbdd422881b3b88f1ad7',
  harnessSourceMapSha256: 'e7a059f8a0855a822e7294ed6fb549b3e3eee9b67d60f1ec1f6cc0c6752bd708',
  sourceMapSha256: 'ef5ee45d5137f71364be01bf849c5771b292d20195e22e9cfd3d0a4fcf45f7c9',
  runSha256: '31420930f9370faf1b4e8e9d5f15b40cb2e70c5d1ec771da2872adafda05b6ec',
  verificationSha256: 'f14c5144542464917b240c2880fb3a1d12514dbb79243d83b7b9531385001ab2',
  semanticEvidenceSha256: 'a49c84d01f17a85691de9d7989fcddfd94aef81283d992e93ce4acd7f7a912c3',
  clauseCount: 901,
  candidateCount: 5,
  citationCount: 63,
  judgmentCount: 9,
  eligibleChainCount: 0,
  transitionReply: 'adelante',
  transitionReplySha256: 'd0355cec890057025372102f42d49459abbe102c85a151023a58e267b0549d40',
});

const ARTIFACT_HASHES = Object.freeze({
  'candidate-index.json': H049.candidateIndexSha256,
  'clause-universe.json': H049.clauseUniverseSha256,
  'harness-source-map.json': H049.harnessSourceMapSha256,
  'run.json': H049.runSha256,
  'source-map.json': H049.sourceMapSha256,
  'verification.json': H049.verificationSha256,
});

const CANONICAL_DIRECTORIES = Object.freeze(['canonical-v2-a', 'canonical-v2-b']);
const POST_REVIEW_SOURCE_PATHS = Object.freeze([
  'lab/h049/post-review.mjs',
  'lab/h049/post-review.test.mjs',
]);
const EXPECTED_CLASSIFICATIONS = Object.freeze([
  ['spec0001-network-reconnect', 'normative-positive'],
  ['adr0006-bounded-surface-thread-mechanism', 'future-precondition'],
  ['spec0002-virtual-action-deadline', 'normative-positive'],
  ['spec0001-button-command-surface', 'normative-positive'],
  ['strongest-cross-domain-composite', 'cross-domain-composite'],
]);

const MOTION_PARAGRAPHS = Object.freeze([
  `Acepto como revisión humana canónica de H‑049 el mapa raw SHA‑256 ${H049.reviewMapRawSha256}, cuyo hash JSON canónico es ${H049.reviewMapCanonicalSha256}.`,
  'Acepto sus cinco clasificaciones, 63 citas, los nueve juicios como resueltos conforme al mapa y el default no-additional-eligible-chain.',
  'En consecuencia, acepto H‑049 como refutada exclusivamente dentro del boundary nominado: cero cadenas normativas completas de siete predicados. Esto no demuestra ausencia de política externa, intención futura, estado live, seguridad, implementación, compliance, drift ni causa.',
  'No activa ADR; authority: none, action: null; y no autoriza commit, push, merge, publicación ni mutación.',
]);
export const H049_CANONICAL_MOTION = MOTION_PARAGRAPHS.join(' ');

const DETERMINATIONS = Object.freeze([
  {
    judgment:
      'acceptance or rejection of all five candidate classifications, every exact citation, and the default disposition over all 901 clauses',
    acceptedDisposition:
      'all-five-classifications-all-63-citations-and-no-additional-eligible-chain-default-accepted',
  },
  {
    judgment:
      'whether SPEC-0001 Linux role binding denotes the linux-operator, module runtime, or production-host environment without implying host lifecycle ownership',
    acceptedDisposition: 'linux-role-binding-does-not-imply-physical-device-lifecycle-ownership',
  },
  {
    judgment:
      'whether SPEC-0001 summary language about one physical or virtual button creates physical MK.2 recovery behavior despite its explicit USB, discovery, and key-press exclusions; the proposed map says no',
    acceptedDisposition:
      'physical-or-virtual-summary-does-not-create-excluded-physical-recovery-behavior',
  },
  {
    judgment:
      "whether SPEC-0001's ordinary button-to-authorized-command surface constitutes restored physical command delivery after recovery; the proposed map says no",
    acceptedDisposition:
      'ordinary-command-surface-does-not-establish-restored-post-recovery-physical-delivery',
  },
  {
    judgment:
      'whether SPEC-0001 retryable network and server reconnect can satisfy physical USB recovery; the proposed map says no',
    acceptedDisposition: 'network-and-server-reconnect-does-not-satisfy-physical-usb-recovery',
  },
  {
    judgment:
      'whether ADR-0006 historical mechanism evidence, may-investigate language, or successor-Slice preconditions create a current automatic recovery duty; the proposed map says no',
    acceptedDisposition:
      'historical-evidence-and-future-preconditions-do-not-create-current-automatic-duty',
  },
  {
    judgment:
      'whether the three-second virtual-invocation-to-visible-server-state rule can act as a physical disconnect-to-command-delivery recovery deadline; the proposed map says no',
    acceptedDisposition: 'virtual-action-deadline-does-not-create-physical-recovery-deadline',
  },
  {
    judgment:
      'whether ADR-0003 generic Linux, API 2.0, build, host, CI, USB, and physical-hardware exclusions create or link a positive MK.2 recovery obligation; the proposed map says no',
    acceptedDisposition:
      'generic-platform-and-exclusion-clauses-do-not-create-positive-mk2-recovery-obligation',
  },
  {
    judgment:
      'whether accepted clauses from SPEC-0001, ADR-0006, ADR-0005, and SPEC-0002 may be joined without an explicit normative edge and despite physical-scope exclusions; the proposed map says no',
    acceptedDisposition:
      'unlinked-cross-record-clauses-cannot-form-a-chain-through-cartesian-mixing',
  },
]);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalValue(value, seen) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    assertion(Number.isFinite(value), 'canonical JSON forbids non-finite numbers');
    return value;
  }
  assertion(typeof value !== 'undefined' && typeof value !== 'function', 'unsupported value');
  assertion(!seen.has(value), 'canonical JSON forbids cycles');
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => canonicalValue(item, seen));
    seen.delete(value);
    return result;
  }
  assertion(
    Object.getPrototypeOf(value) === Object.prototype,
    'canonical JSON requires plain objects'
  );
  const result = {};
  for (const key of Object.keys(value).sort()) result[key] = canonicalValue(value[key], seen);
  seen.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value, new Set()));
}

export function canonicalArtifact(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
}

function readRegularFile(repositoryRoot, relativePath) {
  const absolutePath = path.resolve(repositoryRoot, relativePath);
  assertion(
    absolutePath.startsWith(`${path.resolve(repositoryRoot)}${path.sep}`),
    `path escapes repository: ${relativePath}`
  );
  const metadata = lstatSync(absolutePath);
  assertion(metadata.isFile() && !metadata.isSymbolicLink(), `not a regular file: ${relativePath}`);
  return {
    bytes: readFileSync(absolutePath),
    mode: (metadata.mode & 0o777).toString(8).padStart(4, '0'),
  };
}

function assertRelativePathAbsent(repositoryRoot, relativePath) {
  const absolutePath = path.resolve(repositoryRoot, relativePath);
  try {
    lstatSync(absolutePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new Error(`path must be absent at the pre-review boundary: ${relativePath}`);
}

function assertCanonicalArtifact(bytes, document, label) {
  assertion(bytes.equals(canonicalArtifact(document)), `${label} is not canonical JSON plus LF`);
}

function assertExactKeys(value, expected, label) {
  assertion(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    `${label} keys differ`
  );
}

function validateArchivePath(archivePath) {
  assertion(typeof archivePath === 'string' && archivePath.length > 0, 'empty archive path');
  assertion(
    /^[\x20-\x7e]+$/u.test(archivePath) &&
      !archivePath.includes('\\') &&
      !/^[A-Za-z]:/u.test(archivePath),
    `non-canonical archive path: ${archivePath}`
  );
  assertion(!archivePath.startsWith('/'), `absolute archive path: ${archivePath}`);
  assertion(
    path.posix.normalize(archivePath) === archivePath &&
      !archivePath.split('/').some((part) => part === '' || part === '..' || part === '.'),
    `unsafe archive path: ${archivePath}`
  );
  assertion(Buffer.byteLength(archivePath, 'utf8') <= 100, `ustar path too long: ${archivePath}`);
}

function compareArchivePath(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function writeAscii(buffer, offset, length, value, label) {
  const bytes = Buffer.from(value, 'ascii');
  assertion(bytes.length <= length, `${label} does not fit ustar field`);
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value, label) {
  assertion(Number.isSafeInteger(value) && value >= 0, `${label} is not a safe integer`);
  const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`;
  assertion(encoded.length === length, `${label} does not fit ustar octal field`);
  writeAscii(buffer, offset, length, encoded, label);
}

function readOctal(buffer, offset, length, label) {
  const text = buffer
    .subarray(offset, offset + length)
    .toString('ascii')
    .replace(/\0.*$/u, '')
    .trim();
  assertion(/^[0-7]+$/u.test(text), `${label} is not canonical octal`);
  return Number.parseInt(text, 8);
}

function ustarHeader(member) {
  const header = Buffer.alloc(512);
  writeAscii(header, 0, 100, member.archivePath, 'name');
  writeOctal(header, 100, 8, 0o600, 'mode');
  writeOctal(header, 108, 8, 0, 'uid');
  writeOctal(header, 116, 8, 0, 'gid');
  writeOctal(header, 124, 12, member.bytes.length, 'size');
  writeOctal(header, 136, 12, 0, 'mtime');
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeAscii(header, 257, 6, 'ustar\0', 'magic');
  writeAscii(header, 263, 2, '00', 'version');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeAscii(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `, 'checksum');
  return header;
}

export function buildUstar(inputMembers) {
  assertion(Array.isArray(inputMembers) && inputMembers.length > 0, 'ustar requires members');
  const members = inputMembers
    .map((member) => {
      assertion(Buffer.isBuffer(member.bytes), 'ustar member bytes missing');
      validateArchivePath(member.archivePath);
      return { archivePath: member.archivePath, bytes: member.bytes };
    })
    .sort((left, right) => compareArchivePath(left.archivePath, right.archivePath));
  assertion(
    new Set(members.map(({ archivePath }) => archivePath)).size === members.length,
    'duplicate ustar member'
  );
  const chunks = [];
  for (const member of members) {
    chunks.push(ustarHeader(member), member.bytes);
    const remainder = member.bytes.length % 512;
    if (remainder !== 0) chunks.push(Buffer.alloc(512 - remainder));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function parseUstar(archiveBytes) {
  assertion(Buffer.isBuffer(archiveBytes), 'archive must be bytes');
  assertion(archiveBytes.length % 512 === 0, 'archive length is not block-aligned');
  const members = [];
  let offset = 0;
  let zeroBlocks = 0;
  while (offset < archiveBytes.length) {
    const header = archiveBytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += 512;
      continue;
    }
    assertion(zeroBlocks === 0, 'non-zero data follows ustar terminator');
    assertion(header.subarray(257, 263).equals(Buffer.from('ustar\0')), 'ustar magic differs');
    assertion(header.subarray(263, 265).equals(Buffer.from('00')), 'ustar version differs');
    const expectedChecksum = readOctal(header, 148, 8, 'checksum');
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    assertion(
      checksumHeader.reduce((sum, byte) => sum + byte, 0) === expectedChecksum,
      'ustar checksum differs'
    );
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
    validateArchivePath(name);
    assertion(header[156] === 0x30 || header[156] === 0, `non-regular member: ${name}`);
    const mode = readOctal(header, 100, 8, 'mode');
    const uid = readOctal(header, 108, 8, 'uid');
    const gid = readOctal(header, 116, 8, 'gid');
    const byteLength = readOctal(header, 124, 12, 'size');
    const mtime = readOctal(header, 136, 12, 'mtime');
    const dataStart = offset + 512;
    const dataEnd = dataStart + byteLength;
    assertion(dataEnd <= archiveBytes.length, `truncated member: ${name}`);
    const bytes = Buffer.from(archiveBytes.subarray(dataStart, dataEnd));
    const paddedEnd = dataStart + Math.ceil(byteLength / 512) * 512;
    assertion(
      archiveBytes.subarray(dataEnd, paddedEnd).every((byte) => byte === 0),
      `non-zero member padding: ${name}`
    );
    members.push({ archivePath: name, bytes, mode, uid, gid, mtime });
    offset = paddedEnd;
  }
  assertion(zeroBlocks >= 2, 'ustar terminator is incomplete');
  assertion(
    new Set(members.map(({ archivePath }) => archivePath)).size === members.length,
    'duplicate parsed member'
  );
  return members;
}

function inspectPreReview(repositoryRoot) {
  assertRelativePathAbsent(repositoryRoot, '.overlaykit/governance/changes/CHG-0027.json');
  const artifactBytes = new Map();
  for (const directory of CANONICAL_DIRECTORIES) {
    for (const [fileName, expectedSha256] of Object.entries(ARTIFACT_HASHES)) {
      const relativePath = `artifacts/h049/${directory}/${fileName}`;
      const { bytes } = readRegularFile(repositoryRoot, relativePath);
      assertion(sha256(bytes) === expectedSha256, `${relativePath} digest differs`);
      artifactBytes.set(`${directory}/${fileName}`, bytes);
    }
  }
  for (const fileName of Object.keys(ARTIFACT_HASHES)) {
    assertion(
      artifactBytes
        .get(`canonical-v2-a/${fileName}`)
        .equals(artifactBytes.get(`canonical-v2-b/${fileName}`)),
      `canonical copies differ: ${fileName}`
    );
  }

  const harnessSourceMapBytes = artifactBytes.get('canonical-v2-a/harness-source-map.json');
  const harnessSourceMap = parseJson(harnessSourceMapBytes, 'harness source map');
  assertCanonicalArtifact(harnessSourceMapBytes, harnessSourceMap, 'harness source map');
  assertion(harnessSourceMap.hypothesis === H049.hypothesis, 'harness hypothesis differs');
  assertion(harnessSourceMap.sourceCount === 13, 'harness source count differs');
  assertion(
    harnessSourceMap.sourceSetSha256 === H049.harnessSourceSetSha256,
    'harness source-set digest differs'
  );
  assertion(
    sha256(canonicalJson(harnessSourceMap.sources)) === H049.harnessSourceSetSha256,
    'harness source-set preimage differs'
  );

  const sourceBytes = new Map();
  for (const source of harnessSourceMap.sources) {
    assertExactKeys(source, ['byteLength', 'mode', 'path', 'sha256'], 'harness source');
    const current = readRegularFile(repositoryRoot, source.path);
    assertion(current.mode === source.mode, `source mode differs: ${source.path}`);
    assertion(current.bytes.length === source.byteLength, `source length differs: ${source.path}`);
    assertion(sha256(current.bytes) === source.sha256, `source digest differs: ${source.path}`);
    sourceBytes.set(source.path, current.bytes);
  }
  assertion(
    sha256(sourceBytes.get('.overlaykit/governance/changes/CHG-0026.json')) ===
      H049.precontractRawSha256,
    'precontract digest differs'
  );
  assertion(
    sha256(sourceBytes.get('.overlaykit/governance/manifest.json')) ===
      H049.preReviewManifestRawSha256,
    'pre-review manifest digest differs'
  );

  const reviewMapBytes = sourceBytes.get('lab/h049/review-map.json');
  const reviewMap = parseJson(reviewMapBytes, 'review map');
  assertion(sha256(reviewMapBytes) === H049.reviewMapRawSha256, 'review-map raw digest differs');
  assertion(
    sha256(canonicalArtifact(reviewMap)) === H049.reviewMapCanonicalSha256,
    'review-map canonical digest differs'
  );
  assertion(
    reviewMap.status === 'agent-proposed-pending-human-acceptance' &&
      reviewMap.humanAcceptanceRef === null,
    'pre-review map temporal state differs'
  );
  assertion(reviewMap.candidates.length === H049.candidateCount, 'candidate count differs');
  assertion(
    reviewMap.candidates.flatMap(({ citations }) => citations).length === H049.citationCount,
    'citation count differs'
  );
  assertion(
    reviewMap.pendingHumanJudgments.length === H049.judgmentCount,
    'pending judgment count differs'
  );
  assertion(
    canonicalJson(reviewMap.pendingHumanJudgments) ===
      canonicalJson(DETERMINATIONS.map(({ judgment }) => judgment)),
    'pending judgments differ from accepted determinations'
  );
  assertion(
    canonicalJson(reviewMap.candidates.map(({ id, classification }) => [id, classification])) ===
      canonicalJson(EXPECTED_CLASSIFICATIONS),
    'candidate classifications differ'
  );
  assertion(
    reviewMap.defaultDisposition.classification === 'no-additional-eligible-chain' &&
      reviewMap.defaultDisposition.allUnlistedClauses === true &&
      reviewMap.defaultDisposition.humanAcceptanceRequired === true,
    'default disposition differs'
  );

  const candidateIndexBytes = artifactBytes.get('canonical-v2-a/candidate-index.json');
  const candidateIndex = parseJson(candidateIndexBytes, 'candidate index');
  assertCanonicalArtifact(candidateIndexBytes, candidateIndex, 'candidate index');
  assertion(
    canonicalJson(
      candidateIndex.candidates.map(({ eligible, ...candidate }) => {
        assertion(eligible === false, `candidate unexpectedly eligible: ${candidate.id}`);
        return candidate;
      })
    ) === canonicalJson(reviewMap.candidates),
    'candidate index and review map differ'
  );
  assertion(
    candidateIndex.mechanicalCoverageComplete === true,
    'mechanical coverage is incomplete'
  );
  assertion(candidateIndex.eligibleChains.length === 0, 'eligible chains are not zero');
  assertion(
    candidateIndex.unknowns.length === H049.judgmentCount,
    'candidate unknown count differs'
  );
  assertion(
    candidateIndex.semanticReview.status === 'agent-proposed-pending-human-acceptance' &&
      candidateIndex.semanticReview.humanAcceptanceRef === null &&
      candidateIndex.semanticReview.coverageComplete === false,
    'candidate-index pre-review state differs'
  );
  assertion(
    canonicalJson(candidateIndex.semanticReview.pendingHumanJudgments) ===
      canonicalJson(reviewMap.pendingHumanJudgments),
    'candidate-index pending judgments differ'
  );
  assertion(
    canonicalJson(candidateIndex.outcome) ===
      canonicalJson({
        status: 'inconclusive',
        stage: 'semantic-review',
        reasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
      }),
    'candidate-index pre-review outcome differs'
  );
  assertion(
    canonicalJson(candidateIndex.projectedOutcomeIfExactMapAccepted) ===
      canonicalJson({
        status: 'refuted',
        stage: 'closed-accepted-law-boundary',
        reasonCode: 'complete-zero-chain-coverage',
        condition:
          'only-after-exact-map-content-addressed-human-acceptance-and-zero-pending-judgments',
      }),
    'candidate-index accepted projection differs'
  );

  const clauseUniverse = parseJson(
    artifactBytes.get('canonical-v2-a/clause-universe.json'),
    'clause universe'
  );
  assertion(clauseUniverse.clauses.length === H049.clauseCount, 'clause count differs');

  const run = parseJson(artifactBytes.get('canonical-v2-a/run.json'), 'run');
  const verification = parseJson(
    artifactBytes.get('canonical-v2-a/verification.json'),
    'verification'
  );
  assertion(run.semanticEvidenceSha256 === H049.semanticEvidenceSha256, 'run evidence differs');
  assertion(
    verification.semanticEvidenceSha256 === H049.semanticEvidenceSha256,
    'verification evidence differs'
  );
  assertion(verification.verified === true, 'independent verification is not true');
  assertion(
    canonicalJson(run.outcome) === canonicalJson(candidateIndex.outcome) &&
      canonicalJson(verification.outcome) === canonicalJson(candidateIndex.outcome),
    'pre-review outcomes differ'
  );
  assertion(run.authority === 'none' && run.action === null, 'run grants authority');
  assertion(
    verification.authority === 'none' && verification.action === null,
    'verification grants authority'
  );
  return {
    artifactBytes,
    harnessSourceMap,
    sourceBytes,
    reviewMap,
    candidateIndex,
    run,
    verification,
  };
}

export function assertBuildInputsStable(repositoryRoot, inputSnapshot) {
  assertRelativePathAbsent(repositoryRoot, '.overlaykit/governance/changes/CHG-0027.json');
  for (const source of inputSnapshot.harnessSourceMap.sources) {
    const current = readRegularFile(repositoryRoot, source.path);
    assertion(current.mode === source.mode, `postflight source mode differs: ${source.path}`);
    assertion(
      current.bytes.equals(inputSnapshot.sourceBytes.get(source.path)),
      `postflight source bytes differ: ${source.path}`
    );
  }
  for (const [sourcePath, expectedBytes] of inputSnapshot.postReviewSourceBytes) {
    const current = readRegularFile(repositoryRoot, sourcePath);
    assertion(current.mode === '0644', `postflight replay source mode differs: ${sourcePath}`);
    assertion(
      current.bytes.equals(expectedBytes),
      `postflight replay source bytes differ: ${sourcePath}`
    );
  }
}

function buildSourceAnchor(preReview) {
  return {
    schemaVersion: 'overlaykit-h049-local-source-anchor/v1',
    repository: 'github.com/OverlayKit/companion-module-overlaykit-server',
    capturedOn: H049.acceptedOn,
    admission: {
      kind: 'local-content-addressed-unsigned',
      signatureStatus: 'absent-not-authorized',
      commit: null,
    },
    temporalBoundary:
      'exact pre-review worktree bytes captured before CHG-0027 and its successor manifest entry exist',
    precontract: {
      id: H049.precontract,
      status: 'proposed',
      rawSha256: H049.precontractRawSha256,
    },
    preReviewManifestRawSha256: H049.preReviewManifestRawSha256,
    sourceSetSha256: H049.harnessSourceSetSha256,
    sourceCount: preReview.harnessSourceMap.sourceCount,
    sources: preReview.harnessSourceMap.sources,
    provenanceLimit:
      'content addressing proves byte identity inside this local closure but does not provide signed Git provenance, remote durability, publication, or independent timestamp authority',
    authority: 'none',
    action: null,
  };
}

function buildHumanAcceptance() {
  const canonicalTextSha256 = sha256(H049_CANONICAL_MOTION);
  return {
    schemaVersion: 'overlaykit-h049-human-acceptance/v1',
    principal: H049.principal,
    acceptedOn: H049.acceptedOn,
    canonicalization:
      'UTF-8; trim each displayed paragraph; collapse display wrapping to U+0020; join paragraphs with one U+0020; no trailing LF',
    motion: {
      id: 'H049_CANONICAL_POST_REVIEW_ACCEPTANCE',
      canonicalTextSha256,
      canonicalText: H049_CANONICAL_MOTION,
      authorizes: [
        'accept the exact H-049 review map, five classifications, 63 citations, nine judgments, and complete default disposition',
        'adjudicate H-049 as refuted only inside the exact nominated accepted-law boundary',
      ],
      withholds: [
        'commit',
        'push',
        'merge',
        'raw-artifact publication',
        'ADR creation',
        'SPEC creation or change',
        'production policy',
        'live or host observation',
        'USB or hidraw access',
        'product or host mutation',
        'operational action authority',
      ],
    },
    successorTransition: {
      reply: H049.transitionReply,
      replySha256: H049.transitionReplySha256,
      interpretationKind: 'context-bound-inference',
      authorizes:
        'local content-addressed successor materialization and required local verification gates only',
      doesNotAuthorize:
        'signed Git provenance, commit, push, merge, publication, ADR, SPEC, product policy, live observation, or host mutation',
      priorWithholdingInterpretation:
        'the contextual reply narrows the earlier mutation withholding only for this local administrative evidence materialization; every operational and remote withholding remains in force',
    },
    scope: {
      hypothesis: H049.hypothesis,
      governancePrecontract: H049.precontract,
      subjectCommit: H049.subjectCommit,
      subjectTree: H049.subjectTree,
      subjectSourceSetSha256: H049.subjectSourceSetSha256,
      harnessSourceSetSha256: H049.harnessSourceSetSha256,
      semanticEvidenceSha256: H049.semanticEvidenceSha256,
      runSha256: H049.runSha256,
      verificationSha256: H049.verificationSha256,
      reviewMapRawSha256: H049.reviewMapRawSha256,
      reviewMapCanonicalJsonSha256: H049.reviewMapCanonicalSha256,
      clauseUniverseSha256: H049.clauseUniverseSha256,
      candidateCount: H049.candidateCount,
      citationCount: H049.citationCount,
      judgmentCount: H049.judgmentCount,
      defaultDisposition: 'no-additional-eligible-chain',
    },
    determinations: DETERMINATIONS,
    temporalInterpretation: {
      mechanicalRunStatus: 'inconclusive',
      mechanicalRunStage: 'semantic-review',
      mechanicalRunReasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
      mechanicalCoverageComplete: true,
      pendingHumanJudgmentCountBeforeReview: H049.judgmentCount,
      mechanicalEvidenceMutated: false,
      reviewMapMutated: false,
      postReviewHypothesisStatus: 'refuted',
      postReviewStage: 'closed-accepted-law-boundary',
      postReviewReasonCode: 'complete-zero-chain-coverage',
      eligibleChainCount: H049.eligibleChainCount,
    },
    claimBoundary: {
      proves: [
        'the exact nominated accepted-law boundary contains zero complete explicit seven-predicate normative chains requiring bounded automatic post-login physical MK.2 command-delivery recovery',
      ],
      excludes: [
        'external policy',
        'future product intent',
        'live host state',
        'recovery safety',
        'implementation',
        'compliance',
        'drift',
        'cause',
        'controller or remediation authority',
      ],
    },
    adrAssessment: {
      status: 'no-decision-candidate-activated',
      reasonCode: 'normative-refutation-selects-no-new-architecture',
      authority: 'none',
      action: null,
    },
    rawArtifacts: {
      disclosure: 'restricted-local-raw',
      publication: 'not-authorized',
      remainLocal: true,
    },
    authority: 'none',
    action: null,
  };
}

function buildPostReviewAssessment(preReview, acceptanceSha256) {
  return {
    schemaVersion: 'overlaykit-h049-post-review-assessment/v1',
    hypothesis: H049.hypothesis,
    createdOn: H049.acceptedOn,
    preReviewEvidence: {
      semanticEvidenceSha256: H049.semanticEvidenceSha256,
      runSha256: H049.runSha256,
      verificationSha256: H049.verificationSha256,
      candidateIndexSha256: H049.candidateIndexSha256,
      clauseUniverseSha256: H049.clauseUniverseSha256,
      harnessSourceMapSha256: H049.harnessSourceMapSha256,
      sourceMapSha256: H049.sourceMapSha256,
      reviewMapRawSha256: H049.reviewMapRawSha256,
      reviewMapCanonicalJsonSha256: H049.reviewMapCanonicalSha256,
      mechanicalOutcome: preReview.run.outcome,
      mechanicalCoverageComplete: true,
      pendingHumanJudgmentCount: H049.judgmentCount,
      candidateCount: H049.candidateCount,
      citationCount: H049.citationCount,
      clauseCount: H049.clauseCount,
      eligibleChainCount: H049.eligibleChainCount,
      mutated: false,
    },
    humanReview: {
      principal: H049.principal,
      acceptedOn: H049.acceptedOn,
      canonicalMotionSha256: sha256(H049_CANONICAL_MOTION),
      humanAcceptanceSha256: acceptanceSha256,
      acceptedReviewMap: true,
      acceptedCandidateCount: H049.candidateCount,
      acceptedCitationCount: H049.citationCount,
      acceptedDefaultDisposition: 'no-additional-eligible-chain',
      closedJudgments: preReview.reviewMap.pendingHumanJudgments,
      closedJudgmentCount: H049.judgmentCount,
      remainingJudgmentCount: 0,
    },
    postReviewAdjudication: {
      status: 'refuted',
      stage: 'closed-accepted-law-boundary',
      reasonCode: 'complete-zero-chain-coverage',
      eligibleChainCount: H049.eligibleChainCount,
      derivation: [
        'the immutable clause universe contains all 901 string clauses in the nine-source boundary',
        'the exact review map classifies five candidates with 63 exact citations',
        'the human principal accepted all five classifications, all citations, all nine judgments, and the complete default disposition',
        'mechanical coverage was complete and the accepted semantic review leaves zero pending judgments',
        'zero explicit complete seven-predicate normative chains remain inside the exact nominated boundary',
      ],
    },
    claimBoundary: {
      subjectCommit: H049.subjectCommit,
      subjectTree: H049.subjectTree,
      proves: [
        'zero complete explicit seven-predicate bounded automatic physical MK.2 recovery obligations in the nominated accepted-law boundary',
      ],
      doesNotProve: [
        'absence of external policy',
        'future product intent',
        'live host state',
        'recovery safety',
        'implementation',
        'compliance',
        'drift',
        'cause',
      ],
    },
    sourceProvenance: {
      kind: 'local-content-addressed-unsigned',
      sourceSetSha256: H049.harnessSourceSetSha256,
      signedGitAnchor: false,
      durabilityClaimed: false,
    },
    adrAssessment: {
      status: 'no-decision-candidate-activated',
      reasonCode: 'normative-refutation-selects-no-product-or-production-architecture',
      futureDecisionQuestion:
        'whether the human principal wants a successor product specification for physical MK.2 recovery',
      futureDecisionAuthorized: false,
      authority: 'none',
      action: null,
    },
    authority: 'none',
    action: null,
  };
}

function member(role, sourceRelativePath, archivePath, bytes) {
  validateArchivePath(archivePath);
  return {
    role,
    sourceRelativePath,
    archivePath,
    sha256: sha256(bytes),
    byteLength: bytes.length,
    mode: '0600',
  };
}

function disclosureScan(items) {
  const signatures = {
    privateKeySignatureFiles: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/u,
    cloudKeySignatureFiles: /\bAKIA[0-9A-Z]{16}\b/u,
    githubTokenSignatureFiles: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
    slackTokenSignatureFiles: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u,
    credentialUrlSignatureFiles: /https?:\/\/[^/\s:@]+:[^/\s@]+@/u,
  };
  const counts = Object.fromEntries(Object.keys(signatures).map((key) => [key, 0]));
  for (const bytes of items) {
    const text = bytes.toString('utf8');
    for (const [key, pattern] of Object.entries(signatures)) {
      if (pattern.test(text)) counts[key] += 1;
    }
  }
  return counts;
}

export function buildPostReviewClosure({ repositoryRoot = REPOSITORY_ROOT } = {}) {
  const preReview = inspectPreReview(repositoryRoot);
  const postReviewSourceBytes = new Map();
  const sourceAnchor = buildSourceAnchor(preReview);
  const sourceAnchorBytes = canonicalArtifact(sourceAnchor);
  const humanAcceptance = buildHumanAcceptance();
  const humanAcceptanceBytes = canonicalArtifact(humanAcceptance);
  const humanAcceptanceSha256 = sha256(humanAcceptanceBytes);
  const postReviewAssessment = buildPostReviewAssessment(preReview, humanAcceptanceSha256);
  const postReviewAssessmentBytes = canonicalArtifact(postReviewAssessment);

  assertion(
    sha256(H049.transitionReply) === H049.transitionReplySha256,
    'successor transition reply digest differs'
  );
  assertion(
    humanAcceptance.determinations.length === H049.judgmentCount,
    'acceptance determination count differs'
  );

  const payloads = [];
  for (const directory of CANONICAL_DIRECTORIES) {
    for (const fileName of Object.keys(ARTIFACT_HASHES).sort()) {
      const sourceRelativePath = `artifacts/h049/${directory}/${fileName}`;
      const archivePath = `evidence/${directory}/${fileName}`;
      payloads.push({
        manifest: member(
          `${directory}-${fileName.replace(/\.json$/u, '')}`,
          sourceRelativePath,
          archivePath,
          preReview.artifactBytes.get(`${directory}/${fileName}`)
        ),
        bytes: preReview.artifactBytes.get(`${directory}/${fileName}`),
      });
    }
  }
  for (const source of preReview.harnessSourceMap.sources) {
    payloads.push({
      manifest: member(
        `pre-review-source-${source.path}`,
        source.path,
        `sources/${source.path}`,
        preReview.sourceBytes.get(source.path)
      ),
      bytes: preReview.sourceBytes.get(source.path),
    });
  }
  for (const sourceRelativePath of POST_REVIEW_SOURCE_PATHS) {
    const { bytes } = readRegularFile(repositoryRoot, sourceRelativePath);
    postReviewSourceBytes.set(sourceRelativePath, bytes);
    payloads.push({
      manifest: member(
        `post-review-replay-${path.posix.basename(sourceRelativePath)}`,
        sourceRelativePath,
        `replay/${sourceRelativePath}`,
        bytes
      ),
      bytes,
    });
  }

  const logicalClosureRoot = `artifacts/h049/post-review-closures/${H049.semanticEvidenceSha256}`;
  for (const [role, fileName, bytes] of [
    ['local-unsigned-source-anchor', 'source-anchor.json', sourceAnchorBytes],
    ['human-acceptance', 'human-acceptance.json', humanAcceptanceBytes],
    ['post-review-assessment', 'post-review-assessment.json', postReviewAssessmentBytes],
  ]) {
    payloads.push({
      manifest: member(role, `${logicalClosureRoot}/${fileName}`, `metadata/${fileName}`, bytes),
      bytes,
    });
  }
  payloads.sort((left, right) =>
    compareArchivePath(left.manifest.archivePath, right.manifest.archivePath)
  );

  const manifest = {
    schemaVersion: 'overlaykit-h049-post-review-manifest/v1',
    closurePurpose:
      'exclusive local post-review closure for human-adjudicated H-049 accepted-law evidence',
    hypothesis: {
      id: H049.hypothesis,
      mechanicalOutcome: 'inconclusive',
      mechanicalReasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
      postReviewOutcome: 'refuted',
      postReviewReasonCode: 'complete-zero-chain-coverage',
      claimBoundary: 'exact-nominated-accepted-law-subject-only',
      eligibleChainCount: H049.eligibleChainCount,
    },
    sourceSet: {
      sha256: H049.harnessSourceSetSha256,
      sourceCount: preReview.harnessSourceMap.sourceCount,
      admission: 'local-content-addressed-unsigned',
      signatureStatus: 'absent-not-authorized',
      signedCommit: null,
    },
    evidence: {
      sha256: H049.semanticEvidenceSha256,
      runSha256: H049.runSha256,
      verificationSha256: H049.verificationSha256,
      candidateIndexSha256: H049.candidateIndexSha256,
      clauseUniverseSha256: H049.clauseUniverseSha256,
      harnessSourceMapSha256: H049.harnessSourceMapSha256,
      sourceMapSha256: H049.sourceMapSha256,
      canonicalRunCopies: 2,
      byteIdentical: true,
      independentlyVerified: true,
    },
    humanReview: {
      reviewMapRawSha256: H049.reviewMapRawSha256,
      reviewMapCanonicalJsonSha256: H049.reviewMapCanonicalSha256,
      canonicalMotionSha256: sha256(H049_CANONICAL_MOTION),
      humanAcceptanceSha256,
      acceptedCandidateCount: H049.candidateCount,
      acceptedCitationCount: H049.citationCount,
      pendingJudgmentCountBeforeReview: H049.judgmentCount,
      closedJudgmentCount: H049.judgmentCount,
      remainingJudgmentCount: 0,
      acceptedDefaultDisposition: 'no-additional-eligible-chain',
      principal: H049.principal,
    },
    payloadMemberCount: payloads.length,
    members: payloads.map(({ manifest: entry }) => entry),
    provenance:
      'local content address only; no signed Git anchor, remote durability, publication, or independent timestamp is claimed',
    disclosure: 'restricted-local-raw',
    publication: 'not-authorized',
    authority: 'none',
    action: null,
  };
  const manifestBytes = canonicalArtifact(manifest);
  const archiveMembers = [
    ...payloads.map(({ manifest: entry, bytes }) => ({
      archivePath: entry.archivePath,
      bytes,
    })),
    { archivePath: 'metadata/manifest.json', bytes: manifestBytes },
  ].sort((left, right) => compareArchivePath(left.archivePath, right.archivePath));
  const buildA = buildUstar(archiveMembers);
  const buildB = buildUstar([...archiveMembers].reverse());
  assertion(buildA.equals(buildB), 'independent deterministic archive builds differ');
  const archiveSha256 = sha256(buildA);
  const archiveFileName = `replay-${archiveSha256}.tar`;
  const scan = disclosureScan([
    ...CANONICAL_DIRECTORIES.flatMap((directory) =>
      Object.keys(ARTIFACT_HASHES).map((fileName) =>
        preReview.artifactBytes.get(`${directory}/${fileName}`)
      )
    ),
    sourceAnchorBytes,
    humanAcceptanceBytes,
    postReviewAssessmentBytes,
    manifestBytes,
  ]);
  assertion(
    Object.values(scan).every((count) => count === 0),
    'bounded disclosure scan failed'
  );

  const closure = {
    schemaVersion: 'overlaykit-h049-post-review-closure/v1',
    createdOn: H049.acceptedOn,
    hypothesis: H049.hypothesis,
    subject: {
      commit: H049.subjectCommit,
      tree: H049.subjectTree,
      sourceCount: 9,
      sourceSetSha256: H049.subjectSourceSetSha256,
      restrictedLsTreeSha256: H049.subjectRestrictedLsTreeSha256,
      planRawSha256: H049.planRawSha256,
      planHash: H049.planHash,
    },
    sourceAnchor: {
      admission: 'local-content-addressed-unsigned',
      signatureStatus: 'absent-not-authorized',
      signedCommit: null,
      sourceSetSha256: H049.harnessSourceSetSha256,
      recordSha256: sha256(sourceAnchorBytes),
      durabilityClaimed: false,
    },
    reviewMap: {
      rawSha256: H049.reviewMapRawSha256,
      canonicalJsonSha256: H049.reviewMapCanonicalSha256,
      sourceStatus: 'agent-proposed-pending-human-acceptance',
      sourceHumanAcceptanceRef: null,
      mutatedAfterReview: false,
    },
    mechanicalEvidence: {
      semanticEvidenceSha256: H049.semanticEvidenceSha256,
      runSha256: H049.runSha256,
      verificationSha256: H049.verificationSha256,
      candidateIndexSha256: H049.candidateIndexSha256,
      clauseUniverseSha256: H049.clauseUniverseSha256,
      harnessSourceMapSha256: H049.harnessSourceMapSha256,
      sourceMapSha256: H049.sourceMapSha256,
      canonicalCopies: 2,
      byteIdentical: true,
      verified: true,
      outcome: preReview.run.outcome,
      mechanicalCoverageComplete: true,
      pendingHumanJudgmentCount: H049.judgmentCount,
      candidateCount: H049.candidateCount,
      citationCount: H049.citationCount,
      clauseCount: H049.clauseCount,
      eligibleChainCount: H049.eligibleChainCount,
      mutatedAfterReview: false,
    },
    humanReview: {
      principal: H049.principal,
      canonicalMotionSha256: sha256(H049_CANONICAL_MOTION),
      transitionReplySha256: H049.transitionReplySha256,
      humanAcceptanceSha256,
      postReviewAssessmentSha256: sha256(postReviewAssessmentBytes),
      closedJudgmentCount: H049.judgmentCount,
      remainingJudgmentCount: 0,
    },
    postReviewAdjudication: {
      status: 'refuted',
      stage: 'closed-accepted-law-boundary',
      reasonCode: 'complete-zero-chain-coverage',
      eligibleChainCount: H049.eligibleChainCount,
      claimBoundary: 'exact-nominated-accepted-law-subject-only',
    },
    manifestSha256: sha256(manifestBytes),
    bundle: {
      path: `${logicalClosureRoot}/${archiveFileName}`,
      sha256: archiveSha256,
      byteLength: buildA.length,
      memberCount: archiveMembers.length,
      format: 'POSIX ustar',
      mode: '0600',
      linkCount: 1,
    },
    determinism: {
      buildASha256: archiveSha256,
      buildBSha256: sha256(buildB),
      byteEqual: true,
      sortedNames: true,
      mtimeEpochSeconds: 0,
      uid: 0,
      gid: 0,
      normalizedMemberMode: '0600',
    },
    verification: {
      memberOrderExact: true,
      memberHashesExact: true,
      memberLengthsExact: true,
      duplicateMembers: 0,
      pathTraversalMembers: 0,
      nonRegularMembers: 0,
      sourceAnchorExact: true,
      sourceSignaturePresent: false,
      canonicalCopiesByteEqual: true,
      mechanicalEvidenceUnchanged: true,
      reviewMapUnchanged: true,
    },
    disclosureScan: {
      scope: 'canonical evidence JSON and post-review metadata',
      ...scan,
    },
    temporalSemantics:
      'the mechanical run and review map remain immutable inconclusive pre-review inputs; only the distinct human review layer adjudicates H-049 as refuted inside the nominated accepted-law boundary',
    adrAssessment: {
      status: 'no-decision-candidate-activated',
      reasonCode: 'normative-refutation-selects-no-new-architecture',
      futureSuccessorSpecificationAuthorized: false,
      authority: 'none',
      action: null,
    },
    provenance:
      'local content-addressed unsigned closure; signed Git identity, remote durability, publication, and independent timestamp remain unclaimed',
    disclosure: 'restricted-local-raw',
    publication: 'not-authorized',
    authority: 'none',
    action: null,
  };
  const closureBytes = canonicalArtifact(closure);
  const inputSnapshot = {
    harnessSourceMap: preReview.harnessSourceMap,
    sourceBytes: preReview.sourceBytes,
    postReviewSourceBytes,
  };
  assertBuildInputsStable(repositoryRoot, inputSnapshot);
  return {
    logicalClosureRoot,
    archiveFileName,
    archiveBytes: buildA,
    closure,
    closureBytes,
    manifest,
    manifestBytes,
    metadata: {
      'source-anchor.json': sourceAnchorBytes,
      'human-acceptance.json': humanAcceptanceBytes,
      'post-review-assessment.json': postReviewAssessmentBytes,
    },
    inputSnapshot,
  };
}

function writeExactFile(filePath, bytes) {
  if (existsSync(filePath)) {
    const metadata = lstatSync(filePath);
    assertion(metadata.isFile() && !metadata.isSymbolicLink(), `unsafe existing file: ${filePath}`);
    assertion(metadata.nlink === 1, `existing file has multiple links: ${filePath}`);
    assertion(
      readFileSync(filePath).equals(bytes),
      `refusing to replace different bytes: ${filePath}`
    );
  } else {
    writeFileSync(filePath, bytes, { flag: 'wx', mode: 0o600 });
  }
  chmodSync(filePath, 0o600);
  const metadata = lstatSync(filePath);
  assertion(
    metadata.isFile() &&
      !metadata.isSymbolicLink() &&
      metadata.nlink === 1 &&
      (metadata.mode & 0o777) === 0o600,
    `written file boundary differs: ${filePath}`
  );
}

function ensureSecureDirectoryPath(allowedRoot, outputDirectory) {
  const normalizedRoot = path.resolve(allowedRoot);
  const normalizedOutput = path.resolve(outputDirectory);
  assertion(
    normalizedOutput.startsWith(`${normalizedRoot}${path.sep}`),
    'closure output escapes its allowed root'
  );
  const rootMetadata = lstatSync(normalizedRoot);
  assertion(
    rootMetadata.isDirectory() && !rootMetadata.isSymbolicLink(),
    'closure allowed root is not a real directory'
  );
  assertion(realpathSync(normalizedRoot) === normalizedRoot, 'closure allowed root uses a symlink');
  let cursor = normalizedRoot;
  for (const component of path.relative(normalizedRoot, normalizedOutput).split(path.sep)) {
    cursor = path.join(cursor, component);
    if (!existsSync(cursor)) mkdirSync(cursor, { mode: 0o700 });
    const metadata = lstatSync(cursor);
    assertion(
      metadata.isDirectory() && !metadata.isSymbolicLink(),
      `closure directory component is unsafe: ${cursor}`
    );
    assertion(
      realpathSync(cursor) === cursor,
      `closure directory component uses a symlink: ${cursor}`
    );
  }
  return normalizedOutput;
}

export function writePostReviewClosure(
  result,
  {
    repositoryRoot = REPOSITORY_ROOT,
    outputDirectory = path.resolve(repositoryRoot, result.logicalClosureRoot),
    allowedRoot = path.resolve(repositoryRoot, 'artifacts/h049'),
  } = {}
) {
  assertBuildInputsStable(repositoryRoot, result.inputSnapshot);
  const secureOutputDirectory = ensureSecureDirectoryPath(allowedRoot, outputDirectory);
  chmodSync(secureOutputDirectory, 0o700);
  const directoryMetadata = lstatSync(secureOutputDirectory);
  assertion(
    directoryMetadata.isDirectory() &&
      !directoryMetadata.isSymbolicLink() &&
      (directoryMetadata.mode & 0o777) === 0o700,
    'closure directory boundary differs'
  );
  const expectedNames = [
    'closure.json',
    'human-acceptance.json',
    'manifest.json',
    'post-review-assessment.json',
    result.archiveFileName,
    'source-anchor.json',
  ].sort();
  const existingNames = readdirSync(secureOutputDirectory).sort();
  assertion(
    existingNames.every((name) => expectedNames.includes(name)),
    'closure directory contains unexpected files'
  );
  for (const [fileName, bytes] of Object.entries(result.metadata)) {
    writeExactFile(path.join(secureOutputDirectory, fileName), bytes);
  }
  writeExactFile(path.join(secureOutputDirectory, 'manifest.json'), result.manifestBytes);
  writeExactFile(path.join(secureOutputDirectory, result.archiveFileName), result.archiveBytes);
  writeExactFile(path.join(secureOutputDirectory, 'closure.json'), result.closureBytes);
  assertBuildInputsStable(repositoryRoot, result.inputSnapshot);
  return secureOutputDirectory;
}

function archiveMemberMap(members) {
  return new Map(members.map((entry) => [entry.archivePath, entry]));
}

function writeReconstructionFile(reconstructionRoot, relativePath, bytes, mode) {
  validateArchivePath(relativePath);
  const absolutePath = path.resolve(reconstructionRoot, relativePath);
  assertion(
    absolutePath.startsWith(`${path.resolve(reconstructionRoot)}${path.sep}`),
    `reconstruction path escapes root: ${relativePath}`
  );
  mkdirSync(path.dirname(absolutePath), { recursive: true, mode: 0o700 });
  writeFileSync(absolutePath, bytes, { flag: 'wx', mode });
  chmodSync(absolutePath, mode);
}

function reconstructExpectedClosure(byPath, harnessSourceMap) {
  const reconstructionRoot = mkdtempSync(
    path.join(tmpdir(), 'overlaykit-h049-closure-reconstruction-')
  );
  try {
    for (const source of harnessSourceMap.sources) {
      const archived = byPath.get(`sources/${source.path}`);
      assertion(archived !== undefined, `reconstruction source absent: ${source.path}`);
      writeReconstructionFile(reconstructionRoot, source.path, archived.bytes, 0o644);
    }
    for (const directory of CANONICAL_DIRECTORIES) {
      for (const fileName of Object.keys(ARTIFACT_HASHES)) {
        const archivePath = `evidence/${directory}/${fileName}`;
        const archived = byPath.get(archivePath);
        assertion(archived !== undefined, `reconstruction evidence absent: ${archivePath}`);
        writeReconstructionFile(
          reconstructionRoot,
          `artifacts/h049/${directory}/${fileName}`,
          archived.bytes,
          0o600
        );
      }
    }
    for (const sourcePath of POST_REVIEW_SOURCE_PATHS) {
      const archived = byPath.get(`replay/${sourcePath}`);
      assertion(archived !== undefined, `reconstruction replay source absent: ${sourcePath}`);
      writeReconstructionFile(reconstructionRoot, sourcePath, archived.bytes, 0o644);
    }
    return buildPostReviewClosure({ repositoryRoot: reconstructionRoot });
  } finally {
    rmSync(reconstructionRoot, { recursive: true, force: true });
  }
}

function readClosureFile(closureDirectory, fileName) {
  const filePath = path.join(closureDirectory, fileName);
  const metadata = lstatSync(filePath);
  assertion(
    metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1,
    `unsafe closure file: ${fileName}`
  );
  assertion((metadata.mode & 0o777) === 0o600, `closure file mode differs: ${fileName}`);
  return readFileSync(filePath);
}

export function verifyPostReviewClosure({
  repositoryRoot = REPOSITORY_ROOT,
  closureDirectory = path.resolve(
    repositoryRoot,
    `artifacts/h049/post-review-closures/${H049.semanticEvidenceSha256}`
  ),
} = {}) {
  assertion(
    realpathSync(closureDirectory) === path.resolve(closureDirectory),
    'closure directory or ancestor uses a symlink'
  );
  const directoryMetadata = lstatSync(closureDirectory);
  assertion(
    directoryMetadata.isDirectory() &&
      !directoryMetadata.isSymbolicLink() &&
      (directoryMetadata.mode & 0o777) === 0o700,
    'closure directory boundary differs'
  );
  const closureBytes = readClosureFile(closureDirectory, 'closure.json');
  const closure = parseJson(closureBytes, 'closure');
  assertCanonicalArtifact(closureBytes, closure, 'closure');
  assertion(closure.schemaVersion === 'overlaykit-h049-post-review-closure/v1', 'closure schema');
  assertion(
    closure.mechanicalEvidence.outcome.status === 'inconclusive' &&
      closure.postReviewAdjudication.status === 'refuted',
    'temporal outcomes differ'
  );
  assertion(closure.authority === 'none' && closure.action === null, 'closure grants authority');
  assertion(
    closure.sourceAnchor.signatureStatus === 'absent-not-authorized' &&
      closure.sourceAnchor.signedCommit === null &&
      closure.sourceAnchor.durabilityClaimed === false,
    'closure overclaims provenance'
  );
  const expectedExternalNames = [
    'closure.json',
    'human-acceptance.json',
    'manifest.json',
    'post-review-assessment.json',
    path.basename(closure.bundle.path),
    'source-anchor.json',
  ].sort();
  assertion(
    canonicalJson(readdirSync(closureDirectory).sort()) === canonicalJson(expectedExternalNames),
    'closure directory roster differs'
  );

  const manifestBytes = readClosureFile(closureDirectory, 'manifest.json');
  assertion(sha256(manifestBytes) === closure.manifestSha256, 'manifest digest differs');
  const manifest = parseJson(manifestBytes, 'manifest');
  assertCanonicalArtifact(manifestBytes, manifest, 'manifest');
  assertion(manifest.payloadMemberCount === manifest.members.length, 'payload count differs');
  assertion(
    manifest.sourceSet.signatureStatus === 'absent-not-authorized' &&
      manifest.sourceSet.signedCommit === null,
    'manifest overclaims signature'
  );

  const archivePath = path.join(closureDirectory, path.basename(closure.bundle.path));
  const archiveBytes = readClosureFile(closureDirectory, path.basename(archivePath));
  assertion(sha256(archiveBytes) === closure.bundle.sha256, 'archive digest differs');
  assertion(archiveBytes.length === closure.bundle.byteLength, 'archive length differs');
  const members = parseUstar(archiveBytes);
  assertion(members.length === closure.bundle.memberCount, 'archive member count differs');
  const sortedNames = members
    .map(({ archivePath: memberPath }) => memberPath)
    .sort(compareArchivePath);
  assertion(
    canonicalJson(members.map(({ archivePath: memberPath }) => memberPath)) ===
      canonicalJson(sortedNames),
    'archive member order differs'
  );
  const byPath = archiveMemberMap(members);
  assertion(
    byPath.get('metadata/manifest.json')?.bytes.equals(manifestBytes),
    'archived manifest differs'
  );
  const expectedEntries = [
    ...manifest.members,
    {
      archivePath: 'metadata/manifest.json',
      sha256: closure.manifestSha256,
      byteLength: manifestBytes.length,
      mode: '0600',
    },
  ].sort((left, right) => compareArchivePath(left.archivePath, right.archivePath));
  assertion(
    members.length === expectedEntries.length && byPath.size === expectedEntries.length,
    'archive and manifest member cardinality differ'
  );
  for (const [index, expected] of expectedEntries.entries()) {
    const observed = members[index];
    assertion(observed.archivePath === expected.archivePath, 'archive path differs');
    assertion(
      sha256(observed.bytes) === expected.sha256,
      `member digest differs: ${expected.archivePath}`
    );
    assertion(
      observed.bytes.length === expected.byteLength,
      `member length differs: ${expected.archivePath}`
    );
    assertion(
      observed.mode === 0o600 && observed.uid === 0 && observed.gid === 0 && observed.mtime === 0,
      `member metadata differs: ${expected.archivePath}`
    );
  }
  const reconstructedArchiveBytes = buildUstar(
    expectedEntries.map(({ archivePath: memberPath }) => ({
      archivePath: memberPath,
      bytes: byPath.get(memberPath).bytes,
    }))
  );
  assertion(
    reconstructedArchiveBytes.equals(archiveBytes),
    'archive is not the exact deterministic ustar reconstruction'
  );

  const sourceAnchorBytes = byPath.get('metadata/source-anchor.json').bytes;
  assertion(
    sha256(sourceAnchorBytes) === closure.sourceAnchor.recordSha256,
    'source-anchor digest differs'
  );
  const sourceAnchor = parseJson(sourceAnchorBytes, 'source anchor');
  assertCanonicalArtifact(sourceAnchorBytes, sourceAnchor, 'source anchor');
  assertion(
    sourceAnchor.admission.kind === 'local-content-addressed-unsigned' &&
      sourceAnchor.admission.signatureStatus === 'absent-not-authorized' &&
      sourceAnchor.admission.commit === null,
    'source anchor overclaims signature'
  );
  assertion(
    sha256(canonicalJson(sourceAnchor.sources)) === H049.harnessSourceSetSha256,
    'archived source-set preimage differs'
  );
  for (const source of sourceAnchor.sources) {
    const archived = byPath.get(`sources/${source.path}`);
    assertion(archived !== undefined, `source absent from archive: ${source.path}`);
    assertion(archived.bytes.length === source.byteLength, `source length differs: ${source.path}`);
    assertion(sha256(archived.bytes) === source.sha256, `source digest differs: ${source.path}`);
  }
  const archivedPrecontract = parseJson(
    byPath.get('sources/.overlaykit/governance/changes/CHG-0026.json').bytes,
    'archived precontract'
  );
  assertion(
    archivedPrecontract.id === H049.precontract && archivedPrecontract.status === 'proposed',
    'archived precontract state differs'
  );
  const archivedReviewMapBytes = byPath.get('sources/lab/h049/review-map.json').bytes;
  const archivedReviewMap = parseJson(archivedReviewMapBytes, 'archived review map');
  assertion(sha256(archivedReviewMapBytes) === H049.reviewMapRawSha256, 'archived map digest');
  assertion(
    sha256(canonicalArtifact(archivedReviewMap)) === H049.reviewMapCanonicalSha256,
    'archived map canonical digest'
  );
  assertion(
    archivedReviewMap.status === 'agent-proposed-pending-human-acceptance' &&
      archivedReviewMap.humanAcceptanceRef === null,
    'archived review-map temporal state differs'
  );

  for (const fileName of Object.keys(ARTIFACT_HASHES)) {
    const first = byPath.get(`evidence/canonical-v2-a/${fileName}`).bytes;
    const second = byPath.get(`evidence/canonical-v2-b/${fileName}`).bytes;
    assertion(first.equals(second), `archived canonical copies differ: ${fileName}`);
    assertion(
      sha256(first) === ARTIFACT_HASHES[fileName],
      `archived artifact differs: ${fileName}`
    );
  }
  const archivedHarnessSourceMapBytes = byPath.get(
    'evidence/canonical-v2-a/harness-source-map.json'
  ).bytes;
  const archivedHarnessSourceMap = parseJson(
    archivedHarnessSourceMapBytes,
    'archived harness source map'
  );
  assertCanonicalArtifact(
    archivedHarnessSourceMapBytes,
    archivedHarnessSourceMap,
    'archived harness source map'
  );
  assertion(
    archivedHarnessSourceMap.sourceSetSha256 === H049.harnessSourceSetSha256,
    'archived harness source-set identity differs'
  );

  const acceptanceBytes = byPath.get('metadata/human-acceptance.json').bytes;
  const acceptance = parseJson(acceptanceBytes, 'human acceptance');
  assertCanonicalArtifact(acceptanceBytes, acceptance, 'human acceptance');
  assertion(
    sha256(acceptance.motion.canonicalText) === acceptance.motion.canonicalTextSha256,
    'acceptance motion digest differs'
  );
  assertion(
    acceptance.motion.canonicalText === H049_CANONICAL_MOTION &&
      acceptance.scope.reviewMapRawSha256 === H049.reviewMapRawSha256 &&
      acceptance.scope.reviewMapCanonicalJsonSha256 === H049.reviewMapCanonicalSha256,
    'accepted review identity differs'
  );
  assertion(
    acceptance.determinations.length === H049.judgmentCount &&
      acceptance.authority === 'none' &&
      acceptance.action === null,
    'acceptance boundary differs'
  );

  const assessmentBytes = byPath.get('metadata/post-review-assessment.json').bytes;
  const assessment = parseJson(assessmentBytes, 'post-review assessment');
  assertCanonicalArtifact(assessmentBytes, assessment, 'post-review assessment');
  assertion(
    assessment.humanReview.humanAcceptanceSha256 === sha256(acceptanceBytes),
    'assessment acceptance reference differs'
  );
  assertion(
    assessment.humanReview.closedJudgmentCount === H049.judgmentCount &&
      assessment.humanReview.remainingJudgmentCount === 0 &&
      assessment.postReviewAdjudication.status === 'refuted' &&
      assessment.postReviewAdjudication.eligibleChainCount === 0,
    'post-review adjudication differs'
  );
  assertion(
    assessment.adrAssessment.status === 'no-decision-candidate-activated' &&
      assessment.authority === 'none' &&
      assessment.action === null,
    'assessment activates authority'
  );

  const expected = reconstructExpectedClosure(byPath, archivedHarnessSourceMap);
  assertion(
    expected.archiveFileName === path.basename(closure.bundle.path),
    'archive filename is not content-addressed exactly'
  );
  assertion(expected.manifestBytes.equals(manifestBytes), 'manifest envelope differs');
  assertion(expected.archiveBytes.equals(archiveBytes), 'archive envelope differs');
  assertion(expected.closureBytes.equals(closureBytes), 'closure envelope differs');
  for (const [fileName, expectedBytes] of Object.entries(expected.metadata)) {
    const archivedBytes = byPath.get(`metadata/${fileName}`).bytes;
    assertion(expectedBytes.equals(archivedBytes), `metadata envelope differs: ${fileName}`);
    assertion(
      readClosureFile(closureDirectory, fileName).equals(archivedBytes),
      `external metadata differs from archive: ${fileName}`
    );
  }

  for (const sourcePath of [
    '.overlaykit/governance/changes/CHG-0026.json',
    'lab/h049/review-map.json',
    ...sourceAnchor.sources
      .map(({ path: sourcePath }) => sourcePath)
      .filter((sourcePath) => sourcePath !== '.overlaykit/governance/manifest.json'),
    ...POST_REVIEW_SOURCE_PATHS,
  ]) {
    const uniqueSourcePath = sourcePath;
    const archiveMemberPath = POST_REVIEW_SOURCE_PATHS.includes(uniqueSourcePath)
      ? `replay/${uniqueSourcePath}`
      : `sources/${uniqueSourcePath}`;
    const current = readRegularFile(repositoryRoot, uniqueSourcePath).bytes;
    assertion(
      current.equals(byPath.get(archiveMemberPath).bytes),
      `current preserved source differs: ${uniqueSourcePath}`
    );
  }

  return {
    verified: true,
    hypothesis: H049.hypothesis,
    mechanicalOutcome: closure.mechanicalEvidence.outcome.status,
    postReviewOutcome: closure.postReviewAdjudication.status,
    sourceAdmission: closure.sourceAnchor.admission,
    sourceSignatureStatus: closure.sourceAnchor.signatureStatus,
    signedGitAnchor: false,
    semanticEvidenceSha256: H049.semanticEvidenceSha256,
    humanAcceptanceSha256: sha256(acceptanceBytes),
    postReviewAssessmentSha256: sha256(assessmentBytes),
    manifestSha256: sha256(manifestBytes),
    archiveSha256: sha256(archiveBytes),
    closureSha256: sha256(closureBytes),
    memberCount: members.length,
    authority: 'none',
    action: null,
  };
}

function runCli() {
  const command = process.argv[2];
  if (command === 'build') {
    const result = buildPostReviewClosure();
    const outputDirectory = writePostReviewClosure(result);
    const verification = verifyPostReviewClosure({ closureDirectory: outputDirectory });
    process.stdout.write(`${canonicalJson(verification)}\n`);
    return;
  }
  if (command === 'verify') {
    process.stdout.write(`${canonicalJson(verifyPostReviewClosure())}\n`);
    return;
  }
  throw new Error('usage: node lab/h049/post-review.mjs <build|verify>');
}

if (path.resolve(process.argv[1] ?? '') === MODULE_PATH) runCli();
