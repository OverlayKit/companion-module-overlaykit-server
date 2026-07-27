import { createHash } from 'node:crypto';
import { posix as posixPath } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { parse as parseYaml } from 'yaml';

export const H047_SUBJECT = Object.freeze({
  commit: 'a68ab8f2c8a64828c1c685161ef9319bd8a837c7',
  tree: '9ee6e2f74f7fd6272559d1b91fe4005726cc5b18',
  entryCount: 238,
  lsTreeSha256: 'c9abef88898ec71e5130e041920ca285bce46bbabb08b6a6d885e292295aad05',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
});

export const H047_IMAGE = Object.freeze({
  reference: 'ghcr.io/bitfocus/companion/companion:v4.3.3',
  imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
});

export const H047_SIGNAL_POLICY_ROLE_ORDER = Object.freeze([
  'image',
  'deployment',
  'accepted-governance',
  'lifecycle-wording',
]);

export const H047_SIGNAL_POLICY = Object.freeze({
  version: 'overlaykit-h047-semantic-signal-policy/v2',
  patterns: Object.freeze([
    Object.freeze({ id: 'deploy', source: 'deploy' }),
    Object.freeze({ id: 'lifecycle', source: 'lifecycle' }),
    Object.freeze({ id: 'desired-state', source: 'desired[-_ ]?state' }),
    Object.freeze({ id: 'cardinality', source: 'cardinality' }),
    Object.freeze({ id: 'reconcile', source: 'reconcil' }),
    Object.freeze({ id: 'convergence', source: 'converg' }),
    Object.freeze({ id: 'production-host', source: 'production[-_ ]?host' }),
    Object.freeze({ id: 'linux-production', source: 'linux production' }),
    Object.freeze({ id: 'drift', source: 'drift' }),
    Object.freeze({ id: 'restart-policy', source: 'restart[-_ ]?policy' }),
    Object.freeze({ id: 'restart-policy-camel', source: 'restartPolicy' }),
    Object.freeze({ id: 'restart-yaml', source: 'restart:' }),
    Object.freeze({ id: 'replicas-yaml', source: 'replicas:' }),
    Object.freeze({ id: 'systemd', source: 'systemd' }),
    Object.freeze({ id: 'exec-start', source: 'ExecStart=' }),
  ]),
});

export const H047_CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'whether the exact immutable repository subject contains a fully explicit eight-predicate desired-state chain for the exact accepted Companion image',
    'the exact subject inventory, governance status inventory, image-identity occurrences, and deployment-shaped path inventory',
  ]),
  excludes: Object.freeze([
    'desired state held outside the exact repository subject',
    'current host state, operator intent, compliance, drift, or cause',
    'actual or externally held operational lifecycle ownership',
    'remediation authority, installation, configuration, signaling, restart, reconciliation, or production action',
  ]),
  authority: 'none',
  action: null,
});

export const H047_PREDICATE_NAMES = Object.freeze([
  'currentAcceptedProductionAuthority',
  'exactImageReferenceAndId',
  'linuxProductionHostRoleBinding',
  'desiredPresenceAndCardinality',
  'repositoryDeclaredLifecycleOwnerRole',
  'reconcilerMechanism',
  'absenceToConvergenceRule',
  'explicitLinkClosure',
]);

export const H047_ATOM_KINDS = Object.freeze([
  'effective-authority',
  'production-scope',
  'image-ref',
  'image-id',
  'host-role-definition',
  'deployment-host-binding',
  'desired-presence',
  'cardinality',
  'lifecycle-owner-role',
  'reconciler',
  'absence-condition',
  'convergence-action',
]);

const H047_REVIEW_ATOM_KINDS = new Set(['effective-authority', 'host-role-definition']);

const H047_EXPECTED_TYPED_ATOMS = Object.freeze([
  Object.freeze({
    id: 'atom-spec0001-effective-authority',
    kind: 'effective-authority',
    subjectKey: 'SPEC-0001',
    assertion: Object.freeze({
      authorityId: 'SPEC-0001',
      recordPath: '.overlaykit/governance/specifications/SPEC-0001.json',
      effectiveStatus: 'accepted',
      scopeKey: 'linux-production-control',
    }),
    citationIds: Object.freeze([
      'citation-plan-spec0001-id',
      'citation-plan-spec0001-effective-status',
      'citation-plan-spec0001-content-hash',
      'citation-spec0001-id',
      'citation-spec0001-title',
    ]),
  }),
  Object.freeze({
    id: 'atom-spec0001-host-role-definition',
    kind: 'host-role-definition',
    subjectKey: 'spec-0001-linux-production-host',
    assertion: Object.freeze({
      roleKey: 'spec-0001-linux-production-host',
      statement: 'OverlayKit and Companion are reachable from the Linux production host.',
    }),
    citationIds: Object.freeze(['citation-spec0001-host-role']),
  }),
]);

const H047_EXPECTED_TYPED_EDGE_COUNT = 106;
const H047_EXPECTED_TYPED_EDGE_CLOSURE_SHA256 =
  '72a06238c7ab380eb97ec5cc10789bf23cf191849ba3e381ec4ca3005271fa79';

const range = (prefix, first, last) =>
  Object.freeze(
    Array.from(
      { length: last - first + 1 },
      (_, index) => `${prefix}-${String(first + index).padStart(4, '0')}`
    )
  );

export const H047_EXPECTED_ACCEPTED_IDS = Object.freeze({
  decisions: range('ADR', 1, 6),
  specifications: range('SPEC', 1, 2),
  implementedChanges: Object.freeze([
    'CHG-0001',
    'CHG-0002',
    'CHG-0003',
    'CHG-0004',
    'CHG-0005',
    'CHG-0014',
    'CHG-0016',
    'CHG-0018',
    'CHG-0021',
  ]),
});

export const H047_EXPECTED_DEPLOYMENT_SURFACES = Object.freeze([
  Object.freeze({
    path: '.github/workflows/governance.yml',
    kind: 'ci-workflow',
    disposition: 'repository-ci',
  }),
  Object.freeze({
    path: '.github/workflows/h034-canonical.yml',
    kind: 'ci-workflow',
    disposition: 'ephemeral-lab-ci',
  }),
  Object.freeze({
    path: 'lab/h034/Dockerfile.companion',
    kind: 'dockerfile',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/Dockerfile.overlaykit',
    kind: 'dockerfile',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/Dockerfile.overlaykit-local',
    kind: 'dockerfile',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/compose.local-source.yaml',
    kind: 'compose',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/compose.yaml',
    kind: 'compose',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h038/compose.yaml',
    kind: 'compose',
    disposition: 'ephemeral-lab',
  }),
]);

export const H047_EXPECTED_IDENTITY_PATHS = Object.freeze([
  '.overlaykit/governance/changes/CHG-0008.json',
  '.overlaykit/governance/changes/CHG-0014.json',
  '.overlaykit/governance/changes/CHG-0019.json',
  '.overlaykit/governance/decisions/ADR-0006.json',
  'lab/h034/Dockerfile.companion',
  'lab/h034/inputs.lock.json',
  'lab/h037/acquisition-lib.mjs',
  'lab/h037/verify.mjs',
  'lab/h041/run.mjs',
  'lab/h041/schema.test.mjs',
  'lab/h041/schemas/dynamic-reacquisition-run.schema.json',
  'lab/h041/verify.mjs',
  'lab/h041/verify.test.mjs',
  'lab/h042/run.mjs',
  'lab/h042/runtime-lib.mjs',
  'lab/h042/schema.test.mjs',
  'lab/h042/schemas/surface-worker-recycle-run.schema.json',
  'lab/h042/verify.mjs',
  'lab/h045/admission-lib.mjs',
  'lab/h045/classifier-lib.mjs',
  'lab/h045/observer-lib.mjs',
  'lab/h045/observer-lib.test.mjs',
  'lab/h045/run.test.mjs',
  'lab/h045/schemas/live-run.schema.json',
  'lab/h045/verify.mjs',
  'lab/h045/verify.test.mjs',
]);

export const H047_EXPECTED_IDENTITY_COUNTS = Object.freeze({
  referencePaths: 22,
  imageIdPaths: 25,
  bothPaths: 21,
  unionPaths: 26,
});

const EXPECTED_SURFACE_BY_PATH = new Map(
  H047_EXPECTED_DEPLOYMENT_SURFACES.map((surface) => [surface.path, surface])
);
const EXPECTED_IDENTITY_SET = new Set(H047_EXPECTED_IDENTITY_PATHS);
const ALLOWED_MODES = new Set(['100644', '100755']);

function canonicalValue(value, seen) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON rejects non-finite numbers');
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => canonicalValue(entry, seen));
  if (typeof value !== 'object') {
    throw new TypeError(`canonical JSON rejects ${typeof value}`);
  }
  if (seen.has(value)) throw new TypeError('canonical JSON rejects cyclic values');
  seen.add(value);
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] === undefined) throw new TypeError(`canonical JSON rejects undefined at ${key}`);
    result[key] = canonicalValue(value[key], seen);
  }
  seen.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value, new Set()));
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function scanSemanticSignals(value) {
  const bytes = asBuffer(value, 'signal input');
  let text;
  try {
    text = FATAL_UTF8.decode(bytes);
  } catch {
    return { utf8: false, matches: [] };
  }
  const matches = [];
  for (const pattern of H047_SIGNAL_POLICY.patterns) {
    const expression = new RegExp(pattern.source, 'giu');
    const offsets = [];
    for (const match of text.matchAll(expression)) offsets.push(match.index);
    if (offsets.length > 0) matches.push({ id: pattern.id, count: offsets.length, offsets });
  }
  return { utf8: true, matches };
}

export function semanticSignalRoles(
  value,
  { path = null, acceptedGovernance = false, archiveExpansionRoles = [] } = {}
) {
  const bytes = asBuffer(value, 'semantic role input');
  const scan = scanSemanticSignals(bytes);
  const matchIds = new Set(scan.matches.map(({ id }) => id));
  const roles = new Set(archiveExpansionRoles);
  if (
    bytes.includes(Buffer.from(H047_IMAGE.reference)) ||
    bytes.includes(Buffer.from(H047_IMAGE.imageId))
  ) {
    roles.add('image');
  }
  if (
    matchIds.has('deploy') ||
    (typeof path === 'string' && classifyDeploymentPath(path).deploymentShaped)
  ) {
    roles.add('deployment');
  }
  if (acceptedGovernance) roles.add('accepted-governance');
  if ([...matchIds].some((id) => id !== 'deploy')) roles.add('lifecycle-wording');
  return H047_SIGNAL_POLICY_ROLE_ORDER.filter((role) => roles.has(role));
}

const TAR_BLOCK_BYTES = 512;
const TAR_END_BYTES = TAR_BLOCK_BYTES * 2;
const DEFAULT_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_ARCHIVE_MEMBERS = 256;
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });

export const H047_ARCHIVE_LIMITS = Object.freeze({
  maxDepth: 1,
  maxArchives: 4,
  maxCompressedBytes: 2 * 1024 * 1024,
  maxArchiveDecompressedBytes: 4 * 1024 * 1024,
  maxDecompressedBytes: 8 * 1024 * 1024,
  maxMemberBytes: 512 * 1024,
  maxPayloadBytes: 8 * 1024 * 1024,
  maxMembers: 256,
  maxMemberPathBytes: 256,
  maxVirtualRouteBytes: 1024,
});

function archiveError(message, options) {
  return new Error(`H-047 archive: ${message}`, options);
}

function asBuffer(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Buffer or Uint8Array`);
  }
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function isZero(bytes) {
  for (const byte of bytes) {
    if (byte !== 0) return false;
  }
  return true;
}

function decodeUtf8(bytes, label) {
  try {
    return FATAL_UTF8.decode(bytes);
  } catch (error) {
    throw archiveError(`${label} is not valid UTF-8`, { cause: error });
  }
}

function decodeTarField(bytes, label) {
  const nul = bytes.indexOf(0);
  const content = nul === -1 ? bytes : bytes.subarray(0, nul);
  if (nul !== -1 && !isZero(bytes.subarray(nul))) {
    throw archiveError(`${label} has non-zero bytes after its terminator`);
  }
  return decodeUtf8(content, label);
}

function parseTarNumber(bytes, label, { allowEmpty = true } = {}) {
  if ((bytes[0] & 0x80) !== 0) {
    throw archiveError(`${label} uses unsupported base-256 encoding`);
  }
  if ([...bytes].some((byte) => byte !== 0 && byte !== 0x20 && (byte < 0x30 || byte > 0x37))) {
    throw archiveError(`${label} contains a non-octal byte`);
  }
  const nul = bytes.indexOf(0);
  if (nul !== -1 && [...bytes.subarray(nul)].some((byte) => byte !== 0 && byte !== 0x20)) {
    throw archiveError(`${label} has non-padding bytes after its terminator`);
  }
  const text = (nul === -1 ? bytes : bytes.subarray(0, nul)).toString('ascii').trim();
  if (text === '') {
    if (allowEmpty) return 0;
    throw archiveError(`${label} is empty`);
  }
  if (!/^[0-7]+$/u.test(text)) throw archiveError(`${label} is not a valid octal number`);
  const value = BigInt(`0o${text}`);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw archiveError(`${label} exceeds the safe-integer range`);
  }
  return Number(value);
}

function verifyTarHeader(header, offset) {
  const signature = header.subarray(257, 265);
  const ustar = signature.equals(Buffer.from('ustar\0' + '00', 'ascii'));
  const gnu = signature.equals(Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00]));
  if (!ustar && !gnu) {
    throw archiveError(`header at byte ${offset} has an unsupported tar magic/version`);
  }

  const recorded = parseTarNumber(header.subarray(148, 156), 'header checksum', {
    allowEmpty: false,
  });
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < header.length; index += 1) {
    const byte = index >= 148 && index < 156 ? 0x20 : header[index];
    unsigned += byte;
    signed += byte > 0x7f ? byte - 0x100 : byte;
  }
  if (recorded !== unsigned && recorded !== signed) {
    throw archiveError(`header at byte ${offset} has an invalid checksum`);
  }
}

function tarHeaderPath(header) {
  const name = decodeTarField(header.subarray(0, 100), 'header name');
  const prefix = decodeTarField(header.subarray(345, 500), 'header prefix');
  return prefix === '' ? name : `${prefix}/${name}`;
}

function validateArchiveMemberPath(rawPath, maxPathBytes) {
  if (typeof rawPath !== 'string' || rawPath === '') {
    throw archiveError('member path is empty');
  }
  if (Buffer.byteLength(rawPath, 'utf8') > maxPathBytes) {
    throw archiveError('member path exceeds the supported length');
  }
  if (/[\u0000-\u001f\u007f]/u.test(rawPath)) {
    throw archiveError(`member path contains a control character: ${JSON.stringify(rawPath)}`);
  }
  if (rawPath.includes('\\')) {
    throw archiveError(`member path contains a backslash: ${JSON.stringify(rawPath)}`);
  }
  if (rawPath.includes('!')) {
    throw archiveError(
      `member path contains the reserved route delimiter: ${JSON.stringify(rawPath)}`
    );
  }
  if (rawPath.startsWith('/') || /^[A-Za-z]:/u.test(rawPath)) {
    throw archiveError(`member path is absolute: ${JSON.stringify(rawPath)}`);
  }

  const normalized = rawPath;
  if (rawPath.endsWith('/')) {
    throw archiveError(`regular member path ends with a slash: ${JSON.stringify(rawPath)}`);
  }
  const segments = normalized.split('/');
  if (
    normalized === '' ||
    segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw archiveError(
      `member path is not canonical repository-relative: ${JSON.stringify(rawPath)}`
    );
  }
  return normalized;
}

function paddedTarSize(size) {
  return Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
}

function parseTarGzipMembers(
  archiveBytes,
  {
    maxDecompressedBytes = DEFAULT_MAX_ARCHIVE_BYTES,
    maxMembers = DEFAULT_MAX_ARCHIVE_MEMBERS,
    maxMemberBytes = 512 * 1024,
    maxMemberPathBytes = 256,
  } = {}
) {
  const compressed = asBuffer(archiveBytes, 'archiveBytes');
  if (!Number.isSafeInteger(maxDecompressedBytes) || maxDecompressedBytes < TAR_END_BYTES) {
    throw new TypeError('maxDecompressedBytes must be a safe integer of at least 1024');
  }
  if (!Number.isSafeInteger(maxMembers) || maxMembers < 1) {
    throw new TypeError('maxMembers must be a positive safe integer');
  }
  if (!Number.isSafeInteger(maxMemberBytes) || maxMemberBytes < 1) {
    throw new TypeError('maxMemberBytes must be a positive safe integer');
  }
  if (!Number.isSafeInteger(maxMemberPathBytes) || maxMemberPathBytes < 1) {
    throw new TypeError('maxMemberPathBytes must be a positive safe integer');
  }

  let tar;
  try {
    const decoded = gunzipSync(compressed, {
      info: true,
      maxOutputLength: maxDecompressedBytes,
    });
    if (decoded.engine.bytesWritten !== compressed.length) {
      throw archiveError('gzip stream has trailing bytes');
    }
    tar = decoded.buffer;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('H-047 archive:')) throw error;
    throw archiveError('gzip decoding failed', { cause: error });
  }
  if (tar.length % TAR_BLOCK_BYTES !== 0) {
    throw archiveError('decompressed tar length is not block-aligned');
  }

  const members = new Map();
  const memberRecords = [];
  const seenPaths = new Set();
  let logicalMembers = 0;
  let offset = 0;

  while (offset + TAR_BLOCK_BYTES <= tar.length) {
    const header = tar.subarray(offset, offset + TAR_BLOCK_BYTES);
    if (isZero(header)) {
      if (offset + TAR_END_BYTES > tar.length) {
        throw archiveError('tar terminator is truncated');
      }
      if (!isZero(tar.subarray(offset + TAR_BLOCK_BYTES, offset + TAR_END_BYTES))) {
        throw archiveError('tar terminator contains only one zero block');
      }
      if (!isZero(tar.subarray(offset + TAR_END_BYTES))) {
        throw archiveError('tar has non-zero data after its terminator');
      }
      return {
        members,
        memberRecords,
        decompressedBytes: tar.length,
        logicalMembers,
        regularMembers: members.size,
        directoryMembers: logicalMembers - members.size,
      };
    }

    verifyTarHeader(header, offset);
    const typeByte = header[156];
    const type = typeByte === 0 ? '0' : String.fromCharCode(typeByte);
    if (type !== '0') {
      throw archiveError(
        `strict profile rejects tar member type ${JSON.stringify(type)} at byte ${offset}`
      );
    }
    if (!isZero(header.subarray(157, 257))) {
      throw archiveError(`regular member at byte ${offset} carries a raw link name`);
    }
    const tarMode = parseTarNumber(header.subarray(100, 108), 'member mode', {
      allowEmpty: false,
    });
    const mode = tarMode === 0o644 ? '100644' : tarMode === 0o755 ? '100755' : null;
    if (mode === null) {
      throw archiveError(`member at byte ${offset} has unsupported mode ${tarMode.toString(8)}`);
    }
    const declaredSize = parseTarNumber(header.subarray(124, 136), 'member size', {
      allowEmpty: false,
    });
    const effectiveSize = declaredSize;
    if (effectiveSize > maxMemberBytes) {
      throw archiveError(`member at byte ${offset} exceeds the per-member size limit`);
    }
    const dataOffset = offset + TAR_BLOCK_BYTES;
    const nextOffset = dataOffset + paddedTarSize(effectiveSize);
    if (nextOffset > tar.length || dataOffset + effectiveSize > tar.length) {
      throw archiveError(`member at byte ${offset} is truncated`);
    }
    const body = tar.subarray(dataOffset, dataOffset + effectiveSize);
    if (!isZero(tar.subarray(dataOffset + effectiveSize, nextOffset))) {
      throw archiveError(`member at byte ${offset} has non-zero padding`);
    }
    offset = nextOffset;

    const memberPath = validateArchiveMemberPath(tarHeaderPath(header), maxMemberPathBytes);
    logicalMembers += 1;
    if (logicalMembers > maxMembers) {
      throw archiveError('member count exceeds the configured limit');
    }
    if (seenPaths.has(memberPath)) {
      throw archiveError(`duplicate member path ${JSON.stringify(memberPath)}`);
    }
    seenPaths.add(memberPath);

    members.set(memberPath, Buffer.from(body));
    memberRecords.push({
      path: memberPath,
      headerOffset: dataOffset - TAR_BLOCK_BYTES,
      dataOffset,
      mode,
      byteLength: body.length,
      sha256: sha256(body),
    });
  }

  throw archiveError('tar is missing its two-block terminator');
}

export function readTarGzipMembers(archiveBytes, options = {}) {
  return parseTarGzipMembers(archiveBytes, options).members;
}

function isArchiveMemberPath(memberPath) {
  return /\.(?:tar\.gz|tgz)$/iu.test(memberPath);
}

function isGzipBytes(bytes) {
  return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

function archiveLimit(options, name) {
  const value = options[name] ?? H047_ARCHIVE_LIMITS[name];
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function byteLex(left, right) {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function archiveClosureSha256(members) {
  const closureMaterial = [...members]
    .sort((left, right) => byteLex(left.path, right.path))
    .map((member) => ({
      path: member.path,
      type: member.type,
      mode: member.mode,
      byteLength: member.byteLength,
      sha256: member.sha256,
      nestedArchiveClosureSha256: member.nestedArchiveRef?.closureSha256 ?? null,
    }));
  return sha256(Buffer.from(canonicalJson(closureMaterial), 'utf8'));
}

export function expandTarGzipForest(rootInputs, options = {}) {
  if (!Array.isArray(rootInputs) || rootInputs.length === 0) {
    throw new TypeError('archive forest roots must be a non-empty array');
  }
  const unknownOptions = Object.keys(options).filter(
    (name) => !Object.prototype.hasOwnProperty.call(H047_ARCHIVE_LIMITS, name)
  );
  if (unknownOptions.length > 0) {
    throw new TypeError(`unknown archive limit: ${unknownOptions.sort().join(', ')}`);
  }
  const limits = Object.fromEntries(
    Object.keys(H047_ARCHIVE_LIMITS).map((name) => [name, archiveLimit(options, name)])
  );
  if (limits.maxArchiveDecompressedBytes > limits.maxDecompressedBytes) {
    throw new TypeError('per-archive decompressed limit exceeds the forest limit');
  }
  const rootPaths = new Set();
  const roots = rootInputs
    .map((root) => {
      if (
        root === null ||
        typeof root !== 'object' ||
        Array.isArray(root) ||
        !safePath(root.path) ||
        root.path.includes('!') ||
        !isArchiveMemberPath(root.path)
      ) {
        throw new Error('each archive root must have a safe .tar.gz or .tgz repository path');
      }
      if (rootPaths.has(root.path)) throw new Error(`duplicate archive root: ${root.path}`);
      rootPaths.add(root.path);
      return { path: root.path, bytes: asBuffer(root.bytes, `${root.path} bytes`) };
    })
    .sort((left, right) => byteLex(left.path, right.path));
  const observations = {
    archives: 0,
    compressedBytes: 0,
    decompressedBytes: 0,
    payloadBytes: 0,
    logicalMembers: 0,
    regularMembers: 0,
    directoryMembers: 0,
  };
  const archives = [];
  const members = [];
  const memberContents = new Map();
  const virtualPaths = new Set();

  const visit = (archivePath, bytes, depth, ancestry) => {
    if (depth > limits.maxDepth) throw archiveError('nested archive depth exceeds the limit');
    if (Buffer.byteLength(archivePath, 'utf8') > limits.maxVirtualRouteBytes) {
      throw archiveError('virtual archive route exceeds the global route limit');
    }
    if (!isGzipBytes(bytes)) {
      throw archiveError(`archive ${JSON.stringify(archivePath)} lacks the gzip signature`);
    }
    observations.archives += 1;
    observations.compressedBytes += bytes.length;
    if (observations.archives > limits.maxArchives) {
      throw archiveError('archive count exceeds the global limit');
    }
    if (observations.compressedBytes > limits.maxCompressedBytes) {
      throw archiveError('compressed archive bytes exceed the global limit');
    }
    const remainingDecompressed = limits.maxDecompressedBytes - observations.decompressedBytes;
    const remainingMembers = limits.maxMembers - observations.logicalMembers;
    if (remainingDecompressed < TAR_END_BYTES || remainingMembers < 1) {
      throw archiveError('global archive budget is exhausted');
    }
    const parsed = parseTarGzipMembers(bytes, {
      maxDecompressedBytes: Math.min(limits.maxArchiveDecompressedBytes, remainingDecompressed),
      maxMembers: remainingMembers,
      maxMemberBytes: limits.maxMemberBytes,
      maxMemberPathBytes: limits.maxMemberPathBytes,
    });
    observations.decompressedBytes += parsed.decompressedBytes;
    observations.logicalMembers += parsed.logicalMembers;
    observations.regularMembers += parsed.regularMembers;
    observations.directoryMembers += parsed.directoryMembers;
    if (observations.decompressedBytes > limits.maxDecompressedBytes) {
      throw archiveError('decompressed archive bytes exceed the global limit');
    }
    if (observations.logicalMembers > limits.maxMembers) {
      throw archiveError('archive member count exceeds the global limit');
    }
    const archiveReceipt = {
      virtualPath: archivePath,
      depth,
      ancestry,
      byteLength: bytes.length,
      sha256: sha256(bytes),
      decompressedBytes: parsed.decompressedBytes,
      logicalMembers: parsed.logicalMembers,
      regularMembers: parsed.regularMembers,
      directoryMembers: parsed.directoryMembers,
    };
    archives.push(archiveReceipt);

    const physicalMembers = [];
    const nestedArchives = [];
    const archiveRoles = new Set();
    let recursivePayloadBytes = 0;
    let recursiveMemberCount = parsed.regularMembers;
    for (const record of [...parsed.memberRecords].sort((left, right) =>
      byteLex(left.path, right.path)
    )) {
      const memberBytes = parsed.members.get(record.path);
      const virtualPath = `${archivePath}!/${record.path}`;
      if (Buffer.byteLength(virtualPath, 'utf8') > limits.maxVirtualRouteBytes) {
        throw archiveError('virtual member route exceeds the global route limit');
      }
      if (virtualPaths.has(virtualPath)) {
        throw archiveError(`duplicate virtual member path ${JSON.stringify(virtualPath)}`);
      }
      virtualPaths.add(virtualPath);
      memberContents.set(virtualPath, memberBytes);
      observations.payloadBytes += memberBytes.length;
      if (observations.payloadBytes > limits.maxPayloadBytes) {
        throw archiveError('archive payload bytes exceed the global limit');
      }
      const nestedArchive = isArchiveMemberPath(record.path);
      if (nestedArchive !== isGzipBytes(memberBytes)) {
        throw archiveError(
          `archive extension/signature mismatch for ${JSON.stringify(virtualPath)}`
        );
      }
      const memberRoles = semanticSignalRoles(memberBytes, { path: record.path });
      const virtualReceipt = {
        virtualPath,
        archivePath,
        memberPath: record.path,
        depth,
        headerOffset: record.headerOffset,
        dataOffset: record.dataOffset,
        byteLength: record.byteLength,
        sha256: record.sha256,
        nestedArchive,
        semanticRoles: memberRoles,
      };
      members.push(virtualReceipt);
      let nestedArchiveRef = null;
      if (nestedArchive) {
        const nested = visit(virtualPath, memberBytes, depth + 1, [...ancestry, archivePath]);
        nestedArchiveRef = {
          archiveSha256: nested.archiveSha256,
          closureSha256: nested.closureSha256,
          immediateMemberCount: nested.immediateMemberCount,
          recursiveMemberCount: nested.recursiveMemberCount,
        };
        nestedArchives.push({
          memberPath: record.path,
          ...nestedArchiveRef,
        });
        recursiveMemberCount += nested.recursiveMemberCount;
        recursivePayloadBytes += nested.recursivePayloadBytes;
        for (const role of nested.semanticRoles) archiveRoles.add(role);
      } else {
        recursivePayloadBytes += record.byteLength;
      }
      for (const role of memberRoles) archiveRoles.add(role);
      physicalMembers.push({
        path: record.path,
        type: 'file',
        mode: record.mode,
        byteLength: record.byteLength,
        sha256: record.sha256,
        semanticRoles: memberRoles,
        nestedArchiveRef,
      });
    }
    const totalUncompressedBytes = physicalMembers.reduce(
      (sum, member) => sum + member.byteLength,
      0
    );
    const closureSha256 = archiveClosureSha256(physicalMembers);
    const semanticRoles = H047_SIGNAL_POLICY_ROLE_ORDER.filter((role) => archiveRoles.has(role));
    Object.assign(archiveReceipt, {
      closureSha256,
      recursiveMemberCount,
      totalUncompressedBytes,
      recursivePayloadBytes,
      semanticRoles,
    });
    return {
      policyVersion: 'overlaykit-h047-archive-expansion/v1',
      format: 'tar+gzip',
      state: 'closed',
      archiveSha256: sha256(bytes),
      immediateMemberCount: physicalMembers.length,
      recursiveMemberCount,
      totalUncompressedBytes,
      recursivePayloadBytes,
      closureSha256,
      members: physicalMembers,
      nestedArchives,
      semanticRoles,
    };
  };

  const expandedRoots = roots.map((root) => ({
    rootPath: root.path,
    rootSha256: sha256(root.bytes),
    expansion: visit(root.path, root.bytes, 0, []),
  }));
  archives.sort((left, right) => byteLex(left.virtualPath, right.virtualPath));
  members.sort((left, right) => byteLex(left.virtualPath, right.virtualPath));
  return {
    limits,
    observations,
    archives,
    members,
    memberContents,
    roots: expandedRoots,
  };
}

export function expandTarGzipClosure(rootPath, archiveBytes, options = {}) {
  const forest = expandTarGzipForest([{ path: rootPath, bytes: archiveBytes }], options);
  const root = forest.roots[0];
  return {
    rootPath: root.rootPath,
    rootSha256: root.rootSha256,
    limits: forest.limits,
    observations: forest.observations,
    archives: forest.archives,
    members: forest.members,
    memberContents: forest.memberContents,
    closureSha256: root.expansion.closureSha256,
    expansion: root.expansion,
  };
}

function safePath(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    !value.startsWith('/') &&
    !/^[A-Za-z]:/u.test(value) &&
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    !value.includes('\\') &&
    value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
  );
}

export function parseLsTreeZ(treeBytes) {
  if (!Buffer.isBuffer(treeBytes)) throw new TypeError('ls-tree input must be a Buffer');
  if (treeBytes.length === 0 || treeBytes.at(-1) !== 0) {
    throw new Error('ls-tree stream must be non-empty and NUL terminated');
  }
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const records = [];
  let start = 0;
  const paths = new Set();
  for (let index = 0; index < treeBytes.length; index += 1) {
    if (treeBytes[index] !== 0) continue;
    if (index === start) throw new Error('ls-tree stream contains an empty record');
    const record = decoder.decode(treeBytes.subarray(start, index));
    const match = /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40})\t([\s\S]+)$/u.exec(record);
    if (!match) throw new Error(`malformed ls-tree record at byte ${start}`);
    const [, mode, type, oid, path] = match;
    if (type !== 'blob') throw new Error(`unsupported ls-tree type ${type}: ${path}`);
    if (!ALLOWED_MODES.has(mode)) throw new Error(`unsupported blob mode ${mode}: ${path}`);
    if (!safePath(path)) throw new Error(`unsafe repository path: ${path}`);
    if (paths.has(path)) throw new Error(`duplicate repository path: ${path}`);
    paths.add(path);
    records.push({ mode, type, oid, path });
    start = index + 1;
  }
  const sorted = records.map(({ path }) => path).sort();
  if (canonicalJson(records.map(({ path }) => path)) !== canonicalJson(sorted)) {
    throw new Error('ls-tree paths are not sorted');
  }
  return records;
}

export function sourceSetSha256(entries) {
  if (!Array.isArray(entries)) throw new TypeError('source-set entries must be an array');
  const paths = new Set();
  const records = entries
    .map((entry) => {
      if (
        !entry ||
        !safePath(entry.path) ||
        !ALLOWED_MODES.has(entry.mode) ||
        !Number.isSafeInteger(entry.byteLength) ||
        entry.byteLength < 0 ||
        !/^[0-9a-f]{64}$/u.test(entry.sha256)
      ) {
        throw new Error('source-set entry is incomplete or malformed');
      }
      if (paths.has(entry.path)) throw new Error(`duplicate source-set path: ${entry.path}`);
      paths.add(entry.path);
      return entry;
    })
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const framed = records.map(
    ({ path, mode, byteLength, sha256: digest }) => `${path}\0${mode}\0${byteLength}\0${digest}\0`
  );
  return sha256(Buffer.from(framed.join(''), 'utf8'));
}

export function jsonPointer(value, pointer) {
  if (pointer === '') return value;
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) {
    throw new Error('JSON pointer must be empty or start with /');
  }
  return pointer
    .slice(1)
    .split('/')
    .map((token) => {
      if (/~(?:[^01]|$)/u.test(token)) throw new Error(`invalid JSON pointer escape: ${token}`);
      return token.replace(/~1/gu, '/').replace(/~0/gu, '~');
    })
    .reduce((current, token) => {
      if (
        current === null ||
        typeof current !== 'object' ||
        !Object.prototype.hasOwnProperty.call(current, token)
      ) {
        return undefined;
      }
      return current[token];
    }, value);
}

export function classifyDeploymentPath(path) {
  if (typeof path !== 'string' || !safePath(path)) {
    return {
      deploymentShaped: true,
      recognized: false,
      kind: 'invalid-path',
      disposition: 'unknown',
    };
  }
  const expected = EXPECTED_SURFACE_BY_PATH.get(path);
  if (expected) {
    return {
      deploymentShaped: true,
      recognized: true,
      kind: expected.kind,
      disposition: expected.disposition,
    };
  }
  const basename = path.split('/').at(-1);
  const suspicious =
    /^Dockerfile(?:\..+)?$/u.test(basename) ||
    /^(?:docker-)?compose(?:\.[^/]+)?\.ya?ml$/u.test(basename) ||
    /\.(?:service|socket|timer|target|mount|path|tf|tf\.json|nomad)$/u.test(basename) ||
    /^(?:Chart|values)\.ya?ml$/u.test(basename) ||
    /(?:^|[-_.])(?:deployment|statefulset|daemonset|playbook|kustomization)(?:[-_.]|$)/iu.test(
      basename
    ) ||
    /(?:^|\/)(?:helm|k8s|kubernetes|terraform|ansible)(?:\/|$)/iu.test(path);
  return suspicious
    ? {
        deploymentShaped: true,
        recognized: false,
        kind: 'unknown-deployment-format',
        disposition: 'unknown',
      }
    : {
        deploymentShaped: false,
        recognized: true,
        kind: null,
        disposition: 'not-deployment-shaped',
      };
}

function governanceKind(path) {
  if (/^\.overlaykit\/governance\/decisions\/ADR-[0-9]{4}\.json$/u.test(path)) {
    return 'decision';
  }
  if (/^\.overlaykit\/governance\/specifications\/SPEC-[0-9]{4}\.json$/u.test(path)) {
    return 'specification';
  }
  if (/^\.overlaykit\/governance\/changes\/CHG-[0-9]{4}\.json$/u.test(path)) {
    return 'change';
  }
  return null;
}

export function candidateRole(path, statusMap = {}) {
  const statusRecord =
    statusMap instanceof Map
      ? statusMap.get(path)
      : Object.prototype.hasOwnProperty.call(statusMap, path)
        ? statusMap[path]
        : undefined;
  const status = typeof statusRecord === 'string' ? statusRecord : statusRecord?.status;
  const kind = governanceKind(path);
  if (kind === 'decision') return status === 'accepted' ? 'accepted-decision' : 'unknown-decision';
  if (kind === 'specification') {
    return status === 'accepted' ? 'accepted-specification' : 'unknown-specification';
  }
  if (kind === 'change') {
    if (status === 'implemented') return 'implemented-change';
    if (status === 'proposed') return 'non-authoritative-proposal';
    return 'unknown-change';
  }
  const surface = classifyDeploymentPath(path);
  if (surface.deploymentShaped) {
    if (!surface.recognized) return 'unknown-deployment-surface';
    return surface.kind === 'ci-workflow' ? 'ci-workflow' : 'ephemeral-lab-deployment';
  }
  if (EXPECTED_IDENTITY_SET.has(path)) return 'historical-image-identity-source';
  return 'non-candidate';
}

export function isEligibleChain(predicates) {
  if (
    predicates === null ||
    typeof predicates !== 'object' ||
    Array.isArray(predicates) ||
    canonicalJson(Object.keys(predicates).sort()) !==
      canonicalJson([...H047_PREDICATE_NAMES].sort())
  ) {
    throw new Error('desired-state chain must contain exactly the eight predicates');
  }
  if (Object.values(predicates).some((value) => typeof value !== 'boolean')) {
    throw new Error('desired-state predicates must be booleans');
  }
  return H047_PREDICATE_NAMES.every((name) => predicates[name] === true);
}

export function deriveH047Outcome({ coverageComplete, unknowns, eligibleChains }) {
  if (!Array.isArray(unknowns) || !Array.isArray(eligibleChains)) {
    throw new TypeError('unknowns and eligibleChains must be arrays');
  }
  if (coverageComplete !== true || unknowns.length > 0) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'incomplete-ambiguous-or-unknown-coverage',
    };
  }
  if (eligibleChains.length > 0) {
    return {
      status: 'supported',
      stage: 'desired-state-chain',
      reasonCode: 'eligible-chain-present',
    };
  }
  return {
    status: 'refuted',
    stage: 'complete-repository-inventory',
    reasonCode: 'complete-zero-eligible-chain-coverage',
  };
}

function blobFor(blobsByOid, oid) {
  return blobsByOid instanceof Map ? blobsByOid.get(oid) : blobsByOid?.[oid];
}

function countOccurrences(bytes, needle) {
  let count = 0;
  let offset = 0;
  while ((offset = bytes.indexOf(needle, offset)) !== -1) {
    count += 1;
    offset += needle.length;
  }
  return count;
}

function sameSet(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((entry, index) => entry === sortedRight[index]);
}

function idFromPath(path) {
  return path
    .split('/')
    .at(-1)
    .replace(/\.json$/u, '');
}

function statusCounts(records) {
  const result = { total: records.length };
  for (const { status } of records) result[status] = (result[status] ?? 0) + 1;
  return result;
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${label} is not valid UTF-8 JSON`);
  }
}

function exactObjectKeys(value, expected) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort())
  );
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function expectedReview(roles) {
  const candidate = roles.length > 0;
  return {
    agentDisposition: candidate ? 'candidate' : 'dismissed',
    rationaleCode: candidate ? 'direct-semantic-signal' : 'no-direct-semantic-signal',
    humanDisposition: 'pending',
    humanJudgmentIds: [],
  };
}

function roleMatches({ role, bytes, path, acceptedGovernance, archiveOrigin }) {
  if (archiveOrigin === 'archive-expansion') return ['embedded-archive-member-signal'];
  if (archiveOrigin === 'nested-archive') return ['nested-archive-signal'];
  if (role === 'image') {
    const matches = [];
    if (bytes.includes(Buffer.from(H047_IMAGE.imageId))) matches.push('exact-image-id');
    if (bytes.includes(Buffer.from(H047_IMAGE.reference))) matches.push('exact-image-reference');
    return matches;
  }
  if (role === 'deployment') {
    const surface = classifyDeploymentPath(path);
    return surface.deploymentShaped && surface.recognized
      ? ['recognized-deployment-surface']
      : ['deployment-wording'];
  }
  if (role === 'accepted-governance') {
    return path === '.overlaykit/governance/plan.json'
      ? ['effective-authority-index']
      : acceptedGovernance
        ? ['effective-accepted-record']
        : [];
  }
  if (role === 'lifecycle-wording') return ['predicate-vocabulary'];
  return [];
}

function expectedSignals({
  bytes,
  path,
  blobSha256,
  acceptedGovernance = false,
  archiveExpansionRoles = [],
  archiveOrigin = null,
  archiveClosureSha256 = null,
}) {
  const roles =
    archiveOrigin === 'archive-expansion'
      ? H047_SIGNAL_POLICY_ROLE_ORDER.filter((role) => archiveExpansionRoles.includes(role))
      : semanticSignalRoles(bytes, { path, acceptedGovernance });
  const origin = archiveOrigin === null ? 'raw-blob' : 'archive-expansion';
  return roles.map((role) => ({
    role,
    origin,
    matches: roleMatches({
      role,
      bytes,
      path,
      acceptedGovernance,
      archiveOrigin,
    }),
    evidenceRef:
      archiveOrigin === 'archive-expansion'
        ? `archive-closure-sha256:${archiveClosureSha256}`
        : `blob-sha256:${blobSha256}`,
  }));
}

function expectedArchiveMemberSignals({ bytes, path, sha256: digest, nestedArchiveRoles = [] }) {
  const nested = nestedArchiveRoles.length > 0;
  const roles = nested ? nestedArchiveRoles : semanticSignalRoles(bytes, { path });
  return roles.map((role) => ({
    role,
    origin: 'archive-member',
    matches: roleMatches({
      role,
      bytes,
      path,
      acceptedGovernance: false,
      archiveOrigin: nested ? 'nested-archive' : null,
    }),
    evidenceRef: `sha256:${digest}`,
  }));
}

function selectedValueType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function selectedValueBytes(value, encoding) {
  if (encoding === 'utf8-string' && typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  if (encoding === 'canonical-json' && value !== undefined) {
    return Buffer.from(canonicalJson(value), 'utf8');
  }
  return null;
}

function lineRangeValue(bytes, startLine, endLine) {
  if (
    !Number.isSafeInteger(startLine) ||
    !Number.isSafeInteger(endLine) ||
    startLine < 1 ||
    endLine < startLine
  ) {
    throw new Error('citation line range is invalid');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/\r\n/gu, '\n');
  const lines = text.split('\n');
  if (endLine > lines.length) throw new Error('citation line range exceeds its source');
  return lines.slice(startLine - 1, endLine).join('\n');
}

function yamlPathValue(bytes, segments) {
  if (
    !Array.isArray(segments) ||
    segments.length === 0 ||
    segments.some(
      (segment) =>
        !(
          (typeof segment === 'string' && segment.length > 0) ||
          (Number.isSafeInteger(segment) && segment >= 0)
        )
    )
  ) {
    throw new Error('YAML citation segments are invalid');
  }
  let current = parseYaml(new TextDecoder('utf-8', { fatal: true }).decode(bytes), {
    uniqueKeys: true,
  });
  for (const segment of segments) {
    if (
      current === null ||
      typeof current !== 'object' ||
      !Object.prototype.hasOwnProperty.call(current, segment)
    ) {
      throw new Error('YAML citation path is absent');
    }
    current = current[segment];
  }
  return current;
}

const LINE_CITATION_KINDS = new Set([
  'docker-instruction',
  'javascript-node',
  'shell-command',
  'utf8-line-range',
]);

function selectorStrings(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(selectorStrings);
  if (value !== null && typeof value === 'object') {
    return Object.values(value).flatMap(selectorStrings);
  }
  return [];
}

function validateLineSelector(citation, sourceText) {
  if (
    citation.selector === null ||
    typeof citation.selector !== 'object' ||
    Array.isArray(citation.selector)
  ) {
    throw new Error('line citation selector is malformed');
  }
  if (citation.kind === 'utf8-line-range') {
    if (
      !exactObjectKeys(citation.selector, ['syntax']) ||
      !nonEmptyString(citation.selector.syntax)
    ) {
      throw new Error('line-range syntax selector is malformed');
    }
    return;
  }
  for (const selected of selectorStrings(citation.selector)) {
    if (!sourceText.includes(selected)) {
      throw new Error('typed line selector is absent from the cited value');
    }
  }
  if (citation.kind === 'docker-instruction' && citation.selector.opcode !== undefined) {
    const opcode = citation.selector.opcode;
    const ordinal = citation.selector.ordinal;
    if (
      typeof opcode !== 'string' ||
      !/^[A-Z]+$/u.test(opcode) ||
      !Number.isSafeInteger(ordinal) ||
      ordinal < 1
    ) {
      throw new Error('Docker instruction selector is malformed');
    }
    const allLines = sourceText.split('\n');
    if (!allLines[0].startsWith(`${opcode} `) && allLines[0] !== opcode) {
      throw new Error('Docker instruction opcode does not select the cited value');
    }
  }
}

function validateCitation(
  citation,
  { ownerPath, entryByPath, contentsByPath, archiveForest, archiveRootByPath }
) {
  const common = [
    'id',
    'kind',
    'sourcePath',
    'sourceBlobSha256',
    'selectedType',
    'selectedEncoding',
    'selectedValueSha256',
    'selectedValue',
  ];
  const expectedKeys =
    citation?.kind === 'json-pointer'
      ? [...common, 'pointer']
      : citation?.kind === 'yaml-path'
        ? [...common, 'segments']
        : LINE_CITATION_KINDS.has(citation?.kind)
          ? [...common, 'startLine', 'endLine', 'selector']
          : citation?.kind === 'archive-member'
            ? [...common, 'memberPath', 'memberSha256', 'archiveClosureSha256']
            : null;
  if (
    expectedKeys === null ||
    !exactObjectKeys(citation, expectedKeys) ||
    !/^citation-[a-z0-9-]+$/u.test(citation.id) ||
    citation.sourcePath !== ownerPath ||
    !safePath(citation.sourcePath) ||
    !/^[0-9a-f]{64}$/u.test(citation.sourceBlobSha256) ||
    !/^[0-9a-f]{64}$/u.test(citation.selectedValueSha256)
  ) {
    throw new Error('typed citation shape is invalid');
  }
  const sourceEntry = entryByPath.get(citation.sourcePath);
  const sourceBytes = contentsByPath.get(citation.sourcePath);
  if (
    sourceEntry === undefined ||
    !Buffer.isBuffer(sourceBytes) ||
    sourceEntry.sha256 !== citation.sourceBlobSha256
  ) {
    throw new Error('typed citation source binding differs');
  }

  let actualValue;
  if (citation.kind === 'json-pointer') {
    actualValue = jsonPointer(
      parseJsonBytes(sourceBytes, `citation ${citation.id}`),
      citation.pointer
    );
    if (actualValue === undefined) throw new Error('JSON citation pointer is absent');
  } else if (citation.kind === 'yaml-path') {
    actualValue = yamlPathValue(sourceBytes, citation.segments);
  } else if (LINE_CITATION_KINDS.has(citation.kind)) {
    actualValue = lineRangeValue(sourceBytes, citation.startLine, citation.endLine);
    validateLineSelector(citation, actualValue);
  } else {
    const root = archiveRootByPath.get(citation.sourcePath);
    const expansion = root?.expansion;
    const member = expansion?.members.find(({ path }) => path === citation.memberPath);
    const memberBytes = archiveForest.memberContents.get(
      `${citation.sourcePath}!/${citation.memberPath}`
    );
    if (
      expansion === undefined ||
      member === undefined ||
      !Buffer.isBuffer(memberBytes) ||
      citation.memberSha256 !== member.sha256 ||
      citation.memberSha256 !== sha256(memberBytes) ||
      citation.archiveClosureSha256 !== expansion.closureSha256 ||
      citation.selectedType !== 'binary' ||
      citation.selectedEncoding !== 'raw-bytes' ||
      citation.selectedValue !== null ||
      citation.selectedValueSha256 !== member.sha256
    ) {
      throw new Error('archive-member citation differs from expansion');
    }
    return { id: citation.id, kind: citation.kind, selectedValue: null, citation };
  }

  if (
    selectedValueType(actualValue) !== citation.selectedType ||
    canonicalJson(actualValue) !== canonicalJson(citation.selectedValue)
  ) {
    throw new Error('typed citation selected value differs');
  }
  const selectedBytes = selectedValueBytes(actualValue, citation.selectedEncoding);
  if (selectedBytes === null || sha256(selectedBytes) !== citation.selectedValueSha256) {
    throw new Error('typed citation selected encoding or digest differs');
  }
  return {
    id: citation.id,
    kind: citation.kind,
    selectedValue: actualValue,
    citation,
  };
}

function validateAtom(atom, { ownerPath, citationById, acceptedAuthorityPaths }) {
  if (
    !exactObjectKeys(atom, ['id', 'kind', 'subjectKey', 'assertion', 'citationIds']) ||
    !/^atom-[a-z0-9-]+$/u.test(atom.id) ||
    !H047_REVIEW_ATOM_KINDS.has(atom.kind) ||
    !nonEmptyString(atom.subjectKey) ||
    atom.assertion === null ||
    typeof atom.assertion !== 'object' ||
    Array.isArray(atom.assertion) ||
    !Array.isArray(atom.citationIds) ||
    atom.citationIds.length === 0 ||
    new Set(atom.citationIds).size !== atom.citationIds.length ||
    atom.citationIds.some((id) => !citationById.has(id))
  ) {
    throw new Error('typed atom shape or citations are invalid');
  }
  const citations = atom.citationIds.map((id) => citationById.get(id));
  if (atom.kind === 'effective-authority') {
    if (
      !exactObjectKeys(atom.assertion, [
        'authorityId',
        'recordPath',
        'effectiveStatus',
        'scopeKey',
      ]) ||
      atom.assertion.authorityId !== atom.subjectKey ||
      atom.assertion.recordPath !== ownerPath ||
      atom.assertion.effectiveStatus !== 'accepted' ||
      !acceptedAuthorityPaths.has(ownerPath) ||
      !citations.some(({ selectedValue }) => selectedValue === atom.assertion.authorityId) ||
      !citations.some(({ selectedValue }) => selectedValue === 'accepted')
    ) {
      throw new Error('effective-authority atom is not bound to effective accepted law');
    }
  } else if (atom.kind === 'host-role-definition') {
    if (
      !exactObjectKeys(atom.assertion, ['roleKey', 'statement']) ||
      atom.assertion.roleKey !== atom.subjectKey ||
      !nonEmptyString(atom.assertion.statement) ||
      !citations.some(({ selectedValue }) => selectedValue === atom.assertion.statement)
    ) {
      throw new Error('host-role-definition atom is not bound to its cited statement');
    }
  }
  return {
    id: atom.id,
    kind: atom.kind,
    subjectKey: atom.subjectKey,
    path: ownerPath,
    assertion: atom.assertion,
  };
}

const H047_EDGE_KINDS = new Set([
  'archive-nesting',
  'compose-dockerfile',
  'compose-entrypoint',
  'docker-build-context',
  'dockerfile-copy',
  'dockerfile-entrypoint',
  'dockerfile-package-script',
  'js-command',
  'js-environment-path-binding',
  'js-import',
  'js-path-binding',
  'manifest-record',
  'normative-requires',
  'package-script-entrypoint',
  'package-script-glob-member',
  'package-script-runner',
  'package-workspace-script',
  'plan-record',
  'record-reference',
  'shell-exec',
  'workflow-npm-script',
]);

const H047_EDGE_ROLES = new Set([
  'authority-binding',
  'containment',
  'content-binding',
  'non-normative-reference',
  'normative',
  'operational',
  'verification',
]);

function edgeCitesTarget({ edge, ownerPath, citations }) {
  if (edge.kind === 'docker-build-context') {
    return false;
  }
  const targetPath = edge.target.path;
  const targetName = targetPath.split('/').at(-1);
  const targetId = targetName.replace(/\.[^.]+$/u, '');
  const evidenceText = citations
    .map(({ selectedValue }) =>
      typeof selectedValue === 'string' ? selectedValue : canonicalJson(selectedValue)
    )
    .join('\n');
  const assertionText = canonicalJson(edge.assertion);
  if (edge.kind === 'plan-record') {
    return (
      ownerPath === '.overlaykit/governance/plan.json' &&
      edge.semanticRole === 'authority-binding' &&
      edge.assertion.recordId === targetId &&
      edge.assertion.effectiveStatus === 'accepted' &&
      edge.assertion.contentHash === edge.target.blobSha256 &&
      evidenceText.includes(targetId) &&
      evidenceText.includes(edge.target.blobSha256)
    );
  }
  if (edge.kind === 'manifest-record') {
    return (
      ownerPath === '.overlaykit/governance/manifest.json' &&
      edge.assertion.recordId === targetId &&
      edge.assertion.contentHash === edge.target.blobSha256 &&
      evidenceText.includes(edge.target.blobSha256)
    );
  }
  if (edge.kind === 'archive-nesting') {
    return citations.some(
      ({ citation }) =>
        citation.kind === 'archive-member' &&
        citation.memberPath === targetPath &&
        citation.memberSha256 === edge.target.blobSha256
    );
  }
  if (edge.kind === 'js-import') {
    return citations.some(({ citation }) => {
      const module = citation.selector?.module;
      return (
        typeof module === 'string' &&
        module.startsWith('.') &&
        posixPath.normalize(posixPath.join(posixPath.dirname(ownerPath), module)) === targetPath
      );
    });
  }
  if (edge.kind === 'workflow-npm-script') {
    return targetPath === 'package.json' && /\bnpm run\b/u.test(evidenceText);
  }
  if (edge.kind === 'record-reference') {
    return evidenceText.includes(targetId);
  }
  if (edge.kind === 'normative-requires') {
    return (
      edge.semanticRole === 'normative' &&
      nonEmptyString(edge.assertion.deploymentKey) &&
      (evidenceText.includes(targetPath) || evidenceText.includes(targetId))
    );
  }
  return (
    evidenceText.includes(targetPath) ||
    evidenceText.includes(targetName) ||
    assertionText.includes(targetPath) ||
    assertionText.includes(targetName)
  );
}

function matchesSupportedGlob(path, pattern) {
  const globstarSuffix = '/**/*.test.mjs';
  if (pattern.endsWith(globstarSuffix)) {
    const prefix = pattern.slice(0, -globstarSuffix.length);
    return path.startsWith(`${prefix}/`) && path.endsWith('.test.mjs');
  }
  const singleSuffix = '/*.test.mjs';
  if (pattern.endsWith(singleSuffix) && !pattern.includes('**')) {
    const prefix = pattern.slice(0, -singleSuffix.length);
    return posixPath.dirname(path) === prefix && posixPath.basename(path).endsWith('.test.mjs');
  }
  return false;
}

function expectedDockerContextMembers(entryByPath, ignoreText) {
  const supportedPatterns = [
    '.git',
    '.github',
    'artifacts',
    'build',
    'coverage',
    'dist',
    'node_modules',
    'pkg',
    '*.log',
  ];
  if (canonicalJson(ignoreText.split('\n')) !== canonicalJson(supportedPatterns)) {
    throw new Error('Docker context uses an unsupported ignore policy');
  }
  const ignored = (path) =>
    supportedPatterns.some((pattern) => {
      if (pattern === '*.log') return posixPath.basename(path).endsWith('.log');
      return path === pattern || path.startsWith(`${pattern}/`);
    });
  return [...entryByPath.values()]
    .filter(({ path }) => !ignored(path))
    .map(({ path, sha256: blobSha256 }) => ({ path, blobSha256 }))
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
}

function validateMaterializedEdge({
  edge,
  ownerPath,
  citations,
  entryByPath,
  contentsByPath,
  archiveRootByPath,
}) {
  const targetPath = edge.target.path;
  if (edge.kind === 'archive-nesting') {
    const citation = citations.length === 1 ? citations[0]?.citation : null;
    const member = archiveRootByPath
      .get(ownerPath)
      ?.expansion.members.find(({ path }) => path === targetPath);
    return (
      edge.semanticRole === 'containment' &&
      exactObjectKeys(edge.assertion, ['memberPath', 'nestedClosureSha256']) &&
      citation?.kind === 'archive-member' &&
      edge.assertion.memberPath === targetPath &&
      citation.memberPath === targetPath &&
      citation.memberSha256 === edge.target.blobSha256 &&
      member?.nestedArchiveRef !== null &&
      member?.nestedArchiveRef?.archiveSha256 === edge.target.blobSha256 &&
      member?.nestedArchiveRef?.closureSha256 === edge.assertion.nestedClosureSha256
    );
  }
  if (edge.kind === 'dockerfile-package-script') {
    if (
      targetPath !== 'package.json' ||
      !exactObjectKeys(edge.assertion, ['selector']) ||
      !/^npm run [a-z0-9:-]+$/u.test(edge.assertion.selector) ||
      citations.length !== 1 ||
      citations[0].citation.kind !== 'docker-instruction' ||
      !citations[0].selectedValue.includes(edge.assertion.selector)
    ) {
      return false;
    }
    const packageJson = parseJsonBytes(contentsByPath.get(targetPath), targetPath);
    const scriptName = edge.assertion.selector.slice('npm run '.length);
    return nonEmptyString(packageJson.scripts?.[scriptName]);
  }
  if (edge.kind === 'js-environment-path-binding') {
    if (
      !exactObjectKeys(edge.assertion, ['environmentKey', 'boundDirectory']) ||
      !nonEmptyString(edge.assertion.environmentKey) ||
      !nonEmptyString(edge.assertion.boundDirectory) ||
      citations.length !== 1 ||
      citations[0].citation.kind !== 'javascript-node' ||
      citations[0].citation.selector?.environmentKey !== edge.assertion.environmentKey
    ) {
      return false;
    }
    const expectedLine = `${edge.assertion.environmentKey}: ${edge.assertion.boundDirectory},`;
    return (
      citations[0].selectedValue.trim() === expectedLine &&
      targetPath === posixPath.join(posixPath.dirname(ownerPath), 'companion-entrypoint.sh')
    );
  }
  if (edge.kind === 'package-workspace-script') {
    if (
      ownerPath !== 'package.json' ||
      !exactObjectKeys(edge.assertion, ['scriptName', 'workspaceName']) ||
      !nonEmptyString(edge.assertion.scriptName) ||
      !nonEmptyString(edge.assertion.workspaceName) ||
      citations.length !== 2 ||
      citations.some(({ citation }) => citation.kind !== 'json-pointer')
    ) {
      return false;
    }
    const script = citations.find(
      ({ citation }) => citation.pointer === `/scripts/${edge.assertion.scriptName}`
    )?.selectedValue;
    const workspace = citations.find(({ citation }) =>
      /^\/workspaces\/(?:0|[1-9][0-9]*)$/u.test(citation.pointer)
    )?.selectedValue;
    if (
      typeof script !== 'string' ||
      typeof workspace !== 'string' ||
      !script.includes(`--workspace ${edge.assertion.workspaceName}`) ||
      targetPath !== `${workspace}/package.json`
    ) {
      return false;
    }
    return (
      parseJsonBytes(contentsByPath.get(targetPath), targetPath).name ===
      edge.assertion.workspaceName
    );
  }
  if (edge.kind === 'package-script-glob-member') {
    if (
      ownerPath !== 'package.json' ||
      !exactObjectKeys(edge.assertion, ['scriptName', 'expandedGlob']) ||
      !nonEmptyString(edge.assertion.scriptName) ||
      !nonEmptyString(edge.assertion.expandedGlob) ||
      citations.length !== 1 ||
      citations[0].citation.kind !== 'json-pointer' ||
      citations[0].citation.pointer !== `/scripts/${edge.assertion.scriptName}` ||
      typeof citations[0].selectedValue !== 'string'
    ) {
      return false;
    }
    return (
      citations[0].selectedValue.split(/\s+/u).includes(edge.assertion.expandedGlob) &&
      matchesSupportedGlob(targetPath, edge.assertion.expandedGlob)
    );
  }
  return edgeCitesTarget({ edge, ownerPath, citations });
}

function validateEdge(
  edge,
  { ownerPath, citationById, entryByPath, contentsByPath, archiveRootByPath }
) {
  if (
    !exactObjectKeys(edge, [
      'id',
      'kind',
      'semanticRole',
      'resolution',
      'target',
      'citationIds',
      'assertion',
    ]) ||
    !/^edge-[a-z0-9-]+$/u.test(edge.id) ||
    !H047_EDGE_KINDS.has(edge.kind) ||
    !H047_EDGE_ROLES.has(edge.semanticRole) ||
    edge.resolution !== 'resolved' ||
    edge.target === null ||
    typeof edge.target !== 'object' ||
    Array.isArray(edge.target) ||
    !Array.isArray(edge.citationIds) ||
    edge.citationIds.length === 0 ||
    new Set(edge.citationIds).size !== edge.citationIds.length ||
    edge.citationIds.some((id) => !citationById.has(id)) ||
    edge.assertion === null ||
    typeof edge.assertion !== 'object' ||
    Array.isArray(edge.assertion)
  ) {
    throw new Error('typed edge shape is invalid');
  }
  let targetPath = null;
  let targetPaths;
  if (edge.target.kind === 'path') {
    if (
      !exactObjectKeys(edge.target, ['kind', 'path', 'blobSha256']) ||
      !safePath(edge.target.path) ||
      !/^[0-9a-f]{64}$/u.test(edge.target.blobSha256)
    ) {
      throw new Error('typed path target shape is invalid');
    }
    const target = entryByPath.get(edge.target.path);
    if (target === undefined || target.sha256 !== edge.target.blobSha256) {
      throw new Error('typed edge target binding differs');
    }
    targetPath = edge.target.path;
    targetPaths = [targetPath];
  } else if (edge.target.kind === 'path-set' && edge.kind === 'docker-build-context') {
    if (
      !exactObjectKeys(edge.target, ['kind', 'members', 'closureSha256']) ||
      !Array.isArray(edge.target.members) ||
      edge.target.members.length === 0 ||
      !/^[0-9a-f]{64}$/u.test(edge.target.closureSha256)
    ) {
      throw new Error('typed path-set target shape is invalid');
    }
    targetPaths = [];
    for (const member of edge.target.members) {
      if (
        !exactObjectKeys(member, ['path', 'blobSha256']) ||
        !safePath(member.path) ||
        entryByPath.get(member.path)?.sha256 !== member.blobSha256
      ) {
        throw new Error('typed path-set member binding differs');
      }
      targetPaths.push(member.path);
    }
    if (
      canonicalJson([...targetPaths].sort()) !== canonicalJson(targetPaths) ||
      new Set(targetPaths).size !== targetPaths.length ||
      sha256(canonicalJson(edge.target.members)) !== edge.target.closureSha256
    ) {
      throw new Error('typed path-set closure differs');
    }
  } else {
    throw new Error('typed edge target kind is invalid');
  }
  const citations = edge.citationIds.map((id) => citationById.get(id));
  if (edge.kind === 'docker-build-context') {
    const dockerCitation = citations.find(
      ({ citation }) => citation.sourcePath === ownerPath && citation.kind === 'docker-instruction'
    );
    const ignoreCitation = citations.find(
      ({ citation }) =>
        citation.sourcePath === '.dockerignore' && citation.kind === 'utf8-line-range'
    );
    if (
      citations.length !== 2 ||
      dockerCitation?.selectedValue !== 'COPY . .' ||
      ignoreCitation === undefined ||
      !exactObjectKeys(edge.assertion, ['contextRoot', 'dockerignorePath']) ||
      edge.assertion.contextRoot !== '.' ||
      edge.assertion.dockerignorePath !== '.dockerignore' ||
      canonicalJson(edge.target.members) !==
        canonicalJson(expectedDockerContextMembers(entryByPath, ignoreCitation.selectedValue))
    ) {
      throw new Error('Docker build context does not resolve its exact path set');
    }
  } else if (citations.some(({ citation }) => citation.sourcePath !== ownerPath)) {
    throw new Error('typed edge cites a source outside its owner');
  }
  if (
    edge.kind !== 'docker-build-context' &&
    !validateMaterializedEdge({
      edge,
      ownerPath,
      citations,
      entryByPath,
      contentsByPath,
      archiveRootByPath,
    })
  ) {
    throw new Error('typed edge citation does not resolve its target');
  }
  return {
    id: edge.id,
    kind: edge.kind,
    semanticRole: edge.semanticRole,
    sourcePath: ownerPath,
    targetPath,
    targetPaths,
    assertion: edge.assertion,
  };
}

function nonEmptyFields(value, fields) {
  return fields.every((field) => nonEmptyString(value?.[field]));
}

export function classifyTypedChains({ atoms, edges }) {
  if (!Array.isArray(atoms) || !Array.isArray(edges)) {
    throw new TypeError('typed atoms and edges must be arrays');
  }
  const adjacency = new Map();
  for (const edge of edges) {
    if (edge.kind !== 'normative-requires' || edge.semanticRole !== 'normative') continue;
    if (!adjacency.has(edge.sourcePath)) adjacency.set(edge.sourcePath, new Set());
    adjacency.get(edge.sourcePath).add(edge.targetPath);
  }
  const reachableFrom = (root) => {
    const reached = new Set([root]);
    const pending = [root];
    while (pending.length > 0) {
      const current = pending.shift();
      for (const target of adjacency.get(current) ?? []) {
        if (!reached.has(target)) {
          reached.add(target);
          pending.push(target);
        }
      }
    }
    return reached;
  };
  const authorityAtoms = atoms.filter(({ kind }) => kind === 'effective-authority');
  const hostRoles = new Set(
    atoms.filter(({ kind }) => kind === 'host-role-definition').map(({ subjectKey }) => subjectKey)
  );
  const deploymentKeys = [
    ...new Set(
      atoms
        .map(({ assertion }) => assertion?.deploymentKey)
        .filter((value) => nonEmptyString(value))
    ),
  ].sort();
  const components = [];
  for (const deploymentKey of deploymentKeys) {
    const deploymentAtoms = atoms.filter(
      ({ assertion }) => assertion?.deploymentKey === deploymentKey
    );
    for (const authority of authorityAtoms) {
      const reachable = reachableFrom(authority.path);
      const scoped = deploymentAtoms.filter(({ path }) => reachable.has(path));
      const byKind = new Map(scoped.map((atom) => [atom.kind, atom]));
      const hostBinding = byKind.get('deployment-host-binding');
      const reconciler = byKind.get('reconciler');
      const absence = byKind.get('absence-condition');
      const convergence = byKind.get('convergence-action');
      const cardinality = byKind.get('cardinality');
      const predicates = {
        currentAcceptedProductionAuthority:
          byKind.get('production-scope')?.assertion.scope === 'production',
        exactImageReferenceAndId:
          byKind.get('image-ref')?.assertion.imageReference === H047_IMAGE.reference &&
          byKind.get('image-id')?.assertion.imageId === H047_IMAGE.imageId,
        linuxProductionHostRoleBinding:
          hostBinding !== undefined &&
          hostRoles.has(hostBinding.assertion.roleKey) &&
          hostBinding.assertion.roleKey === 'spec-0001-linux-production-host',
        desiredPresenceAndCardinality:
          byKind.get('desired-presence')?.assertion.present === true &&
          Number.isSafeInteger(cardinality?.assertion.count) &&
          cardinality.assertion.count >= 1,
        repositoryDeclaredLifecycleOwnerRole: nonEmptyString(
          byKind.get('lifecycle-owner-role')?.assertion.roleKey
        ),
        reconcilerMechanism: nonEmptyFields(reconciler?.assertion, [
          'controller',
          'trigger',
          'target',
          'action',
        ]),
        absenceToConvergenceRule:
          nonEmptyFields(absence?.assertion, ['condition']) &&
          nonEmptyFields(convergence?.assertion, ['action', 'postcondition']),
        explicitLinkClosure:
          scoped.length === deploymentAtoms.length &&
          deploymentAtoms.every(({ path }) => reachable.has(path)),
      };
      components.push({
        id: `deployment:${deploymentKey}@${authority.subjectKey}`,
        deploymentKey,
        authorityAtomId: authority.id,
        atomIds: scoped.map(({ id }) => id).sort(),
        predicates,
        disposition: isEligibleChain(predicates) ? 'eligible' : 'incomplete',
        eligible: isEligibleChain(predicates),
      });
    }
  }
  return {
    components,
    eligibleChains: components.filter(({ eligible }) => eligible),
  };
}

function inferContentFormat(path) {
  const name = path.split('/').at(-1);
  if (/\.(?:tar\.gz|tgz)$/iu.test(path)) return 'tar+gzip';
  if (/^Dockerfile(?:\..+)?$/u.test(name)) return 'dockerfile';
  if (/\.json$/iu.test(path)) return 'json';
  if (/\.ya?ml$/iu.test(path)) return 'yaml';
  if (/\.md$/iu.test(path)) return 'markdown';
  if (/\.sh$/iu.test(path)) return 'shell';
  if (/\.(?:[cm]?js|tsx?)$/iu.test(path)) return 'javascript';
  return 'utf8-text';
}

function validateArchiveExpansion({ declared, root, rootPath, archiveForest, archiveRootBySha }) {
  const expected = root.expansion;
  if (
    !exactObjectKeys(declared, [
      'policyVersion',
      'format',
      'state',
      'archiveSha256',
      'immediateMemberCount',
      'recursiveMemberCount',
      'totalUncompressedBytes',
      'recursivePayloadBytes',
      'closureSha256',
      'members',
      'nestedArchives',
    ]) ||
    declared.policyVersion !== 'overlaykit-h047-archive-expansion/v1' ||
    declared.format !== 'tar+gzip' ||
    declared.state !== 'closed' ||
    declared.archiveSha256 !== expected.archiveSha256 ||
    declared.immediateMemberCount !== expected.immediateMemberCount ||
    declared.recursiveMemberCount !== expected.recursiveMemberCount ||
    declared.totalUncompressedBytes !== expected.totalUncompressedBytes ||
    declared.recursivePayloadBytes !== expected.recursivePayloadBytes ||
    declared.closureSha256 !== expected.closureSha256 ||
    !Array.isArray(declared.members) ||
    !Array.isArray(declared.nestedArchives) ||
    declared.members.length !== expected.members.length
  ) {
    throw new Error('archive expansion header differs from reconstructed closure');
  }
  const expectedNestedArchives = expected.nestedArchives.map((nested) => {
    const subjectRoot = archiveRootBySha.get(nested.archiveSha256);
    if (subjectRoot === undefined) {
      throw new Error('nested archive has no content-identical subject root');
    }
    return { ...nested, subjectPath: subjectRoot.rootPath };
  });
  if (canonicalJson(declared.nestedArchives) !== canonicalJson(expectedNestedArchives)) {
    throw new Error('nested archive index differs from reconstructed closure');
  }
  for (let index = 0; index < expected.members.length; index += 1) {
    const member = expected.members[index];
    const receipt = declared.members[index];
    const virtualPath = `${rootPath}!/${member.path}`;
    const bytes = archiveForest.memberContents.get(virtualPath);
    if (!Buffer.isBuffer(bytes)) throw new Error('archive member bytes are unavailable');
    const nestedReceipt = member.nestedArchiveRef
      ? archiveForest.archives.find(({ virtualPath: route }) => route === virtualPath)
      : null;
    const nestedArchiveRef =
      member.nestedArchiveRef === null
        ? null
        : {
            ...member.nestedArchiveRef,
            subjectPath: archiveRootBySha.get(member.nestedArchiveRef.archiveSha256)?.rootPath,
          };
    const roles =
      nestedReceipt === null
        ? semanticSignalRoles(bytes, { path: member.path })
        : nestedReceipt.semanticRoles;
    if (nestedReceipt === null && !scanSemanticSignals(bytes).utf8) {
      throw new Error('opaque non-archive member cannot be dismissed');
    }
    const signals = expectedArchiveMemberSignals({
      bytes,
      path: member.path,
      sha256: member.sha256,
      nestedArchiveRoles: nestedReceipt?.semanticRoles ?? [],
    });
    if (
      !exactObjectKeys(receipt, [
        'path',
        'type',
        'mode',
        'byteLength',
        'sha256',
        'format',
        'signals',
        'review',
        'nestedArchiveRef',
      ]) ||
      receipt.path !== member.path ||
      receipt.type !== member.type ||
      receipt.mode !== member.mode ||
      receipt.byteLength !== member.byteLength ||
      receipt.sha256 !== member.sha256 ||
      receipt.format !== inferContentFormat(member.path) ||
      canonicalJson(receipt.signals) !== canonicalJson(signals) ||
      canonicalJson(receipt.review) !== canonicalJson(expectedReview(roles)) ||
      canonicalJson(receipt.nestedArchiveRef) !== canonicalJson(nestedArchiveRef)
    ) {
      throw new Error(`archive member receipt differs: ${member.path}`);
    }
  }
}

export function buildInventory({ treeBytes, blobsByOid, reviewMap }) {
  const parsedEntries = parseLsTreeZ(treeBytes);
  const unknowns = [];
  const contentsByPath = new Map();
  const entries = parsedEntries.map((entry) => {
    const bytes = blobFor(blobsByOid, entry.oid);
    if (!Buffer.isBuffer(bytes)) {
      unknowns.push({ code: 'blob-unavailable', path: entry.path, oid: entry.oid });
      return { ...entry, available: false, byteLength: null, sha256: null };
    }
    contentsByPath.set(entry.path, bytes);
    return {
      ...entry,
      available: true,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  });

  if (sha256(treeBytes) !== H047_SUBJECT.lsTreeSha256) {
    unknowns.push({ code: 'ls-tree-stream-mismatch' });
  }
  if (entries.length !== H047_SUBJECT.entryCount) {
    unknowns.push({
      code: 'entry-count-mismatch',
      expected: H047_SUBJECT.entryCount,
      actual: entries.length,
    });
  }
  const entryByPath = new Map(entries.map((entry) => [entry.path, entry]));
  let plan = null;
  let manifest = null;
  try {
    plan = parseJsonBytes(
      contentsByPath.get('.overlaykit/governance/plan.json'),
      'compiled governance plan'
    );
    manifest = parseJsonBytes(
      contentsByPath.get('.overlaykit/governance/manifest.json'),
      'governance manifest'
    );
    if (plan.planHash !== H047_SUBJECT.planHash) {
      unknowns.push({ code: 'compiled-plan-hash-mismatch' });
    }
  } catch {
    unknowns.push({ code: 'compiled-governance-unavailable' });
  }

  const governanceRecords = [];
  for (const entry of entries.filter(({ path }) => governanceKind(path) !== null)) {
    const bytes = contentsByPath.get(entry.path);
    if (!bytes) continue;
    try {
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      const expectedId = idFromPath(entry.path);
      if (
        value === null ||
        typeof value !== 'object' ||
        value.id !== expectedId ||
        typeof value.status !== 'string'
      ) {
        unknowns.push({ code: 'malformed-governance-record', path: entry.path });
        continue;
      }
      governanceRecords.push({
        path: entry.path,
        type: governanceKind(entry.path),
        id: value.id,
        status: value.status,
        contentSha256: entry.sha256,
      });
    } catch {
      unknowns.push({ code: 'unparseable-governance-record', path: entry.path });
    }
  }
  governanceRecords.sort((left, right) =>
    Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))
  );
  const decisions = governanceRecords.filter(({ type }) => type === 'decision');
  const specifications = governanceRecords.filter(({ type }) => type === 'specification');
  const changes = governanceRecords.filter(({ type }) => type === 'change');
  const acceptedDecisionIds = decisions
    .filter(({ status }) => status === 'accepted')
    .map(({ id }) => id)
    .sort();
  const acceptedSpecificationIds = specifications
    .filter(({ status }) => status === 'accepted')
    .map(({ id }) => id)
    .sort();
  const implementedChangeIds = changes
    .filter(({ status }) => status === 'implemented')
    .map(({ id }) => id)
    .sort();
  for (const [label, actual, expected] of [
    ['accepted-decisions', acceptedDecisionIds, H047_EXPECTED_ACCEPTED_IDS.decisions],
    [
      'accepted-specifications',
      acceptedSpecificationIds,
      H047_EXPECTED_ACCEPTED_IDS.specifications,
    ],
    ['implemented-changes', implementedChangeIds, H047_EXPECTED_ACCEPTED_IDS.implementedChanges],
  ]) {
    if (!sameSet(actual, expected)) unknowns.push({ code: `${label}-mismatch`, actual });
  }
  if (changes.filter(({ status }) => status === 'proposed').length !== 12) {
    unknowns.push({ code: 'proposed-change-count-mismatch' });
  }

  const acceptedAuthorityPaths = new Set();
  const bindingByPath = new Map();
  for (const record of governanceRecords) {
    if (record.type === 'decision' || record.type === 'specification') {
      const compiled = (record.type === 'decision' ? plan?.decisions : plan?.specifications)?.find(
        ({ id }) => id === record.id
      );
      if (
        compiled === undefined ||
        compiled.contentHash !== record.contentSha256 ||
        compiled.declaredStatus !== record.status
      ) {
        unknowns.push({ code: 'compiled-record-binding-mismatch', path: record.path });
      }
      const binding = {
        source: 'compiled-plan',
        declaredStatus: compiled?.declaredStatus ?? null,
        effectiveStatus: compiled?.effectiveStatus ?? null,
        contentHash: compiled?.contentHash ?? null,
      };
      bindingByPath.set(record.path, binding);
      if (compiled?.effectiveStatus === 'accepted') acceptedAuthorityPaths.add(record.path);
    } else {
      const contentHash = manifest?.changes?.[record.id] ?? null;
      if (contentHash !== record.contentSha256) {
        unknowns.push({ code: 'manifest-change-binding-mismatch', path: record.path });
      }
      bindingByPath.set(record.path, {
        source: 'manifest-and-record-status',
        declaredStatus: record.status,
        effectiveStatus: null,
        contentHash,
      });
    }
  }
  const effectiveDecisionIds = decisions
    .filter((record) => acceptedAuthorityPaths.has(record.path))
    .map(({ id }) => id);
  const effectiveSpecificationIds = specifications
    .filter((record) => acceptedAuthorityPaths.has(record.path))
    .map(({ id }) => id);
  if (!sameSet(effectiveDecisionIds, H047_EXPECTED_ACCEPTED_IDS.decisions)) {
    unknowns.push({ code: 'effective-accepted-decisions-mismatch', actual: effectiveDecisionIds });
  }
  if (!sameSet(effectiveSpecificationIds, H047_EXPECTED_ACCEPTED_IDS.specifications)) {
    unknowns.push({
      code: 'effective-accepted-specifications-mismatch',
      actual: effectiveSpecificationIds,
    });
  }
  const roleStatusMap = Object.fromEntries(
    governanceRecords.map((record) => [
      record.path,
      {
        status:
          record.type === 'decision' || record.type === 'specification'
            ? bindingByPath.get(record.path)?.effectiveStatus
            : record.status,
      },
    ])
  );

  const referenceNeedle = Buffer.from(H047_IMAGE.reference);
  const imageIdNeedle = Buffer.from(H047_IMAGE.imageId);
  const targetOccurrences = [];
  for (const entry of entries) {
    const bytes = contentsByPath.get(entry.path);
    if (!bytes) continue;
    const referenceCount = countOccurrences(bytes, referenceNeedle);
    const imageIdCount = countOccurrences(bytes, imageIdNeedle);
    if (referenceCount > 0 || imageIdCount > 0) {
      targetOccurrences.push({
        path: entry.path,
        referenceCount,
        imageIdCount,
        role: candidateRole(entry.path, roleStatusMap),
      });
    }
  }
  const actualIdentityPaths = targetOccurrences.map(({ path }) => path).sort();
  if (!sameSet(actualIdentityPaths, H047_EXPECTED_IDENTITY_PATHS)) {
    unknowns.push({ code: 'image-identity-path-set-mismatch', actual: actualIdentityPaths });
  }
  const targetOccurrencePathCounts = {
    referencePaths: targetOccurrences.filter(({ referenceCount }) => referenceCount > 0).length,
    imageIdPaths: targetOccurrences.filter(({ imageIdCount }) => imageIdCount > 0).length,
    bothPaths: targetOccurrences.filter(
      ({ referenceCount, imageIdCount }) => referenceCount > 0 && imageIdCount > 0
    ).length,
    unionPaths: targetOccurrences.length,
  };
  if (canonicalJson(targetOccurrencePathCounts) !== canonicalJson(H047_EXPECTED_IDENTITY_COUNTS)) {
    unknowns.push({
      code: 'image-identity-path-count-mismatch',
      actual: targetOccurrencePathCounts,
    });
  }

  const surfaces = [];
  for (const entry of entries) {
    const classification = classifyDeploymentPath(entry.path);
    if (!classification.deploymentShaped) continue;
    surfaces.push({ path: entry.path, ...classification });
    if (!classification.recognized) {
      unknowns.push({ code: 'unknown-deployment-surface', path: entry.path });
    }
  }
  const actualSurfacePaths = surfaces.map(({ path }) => path).sort();
  const expectedSurfacePaths = H047_EXPECTED_DEPLOYMENT_SURFACES.map(({ path }) => path).sort();
  if (!sameSet(actualSurfacePaths, expectedSurfacePaths)) {
    unknowns.push({ code: 'deployment-surface-set-mismatch', actual: actualSurfacePaths });
  }

  const completeEntries = entries.filter(({ available }) => available);
  const sourceMap = {
    subject: H047_SUBJECT,
    entryCount: entries.length,
    entries,
    sourceSetSha256:
      completeEntries.length === entries.length ? sourceSetSha256(completeEntries) : null,
  };

  if (reviewMap?.schemaVersion === 'overlaykit-h047-semantic-review/v2') {
    const mechanicalUnknowns = [...unknowns];
    unknowns.length = 0;
    const humanUnknowns = [];
    const candidates = [];
    const validatedAtoms = [];
    const validatedEdges = [];
    const citationById = new Map();
    const receiptByPath = new Map();
    let archiveForest = {
      observations: {
        archives: 0,
        decompressedBytes: 0,
        payloadBytes: 0,
        logicalMembers: 0,
      },
      roots: [],
      archives: [],
      memberContents: new Map(),
    };
    let reviewShapeValid = true;
    const expectedSignalPolicy = {
      roleOrder: H047_SIGNAL_POLICY_ROLE_ORDER,
      exactImageReference: H047_IMAGE.reference,
      exactImageId: H047_IMAGE.imageId,
      recognizedDeploymentSurfaces: H047_EXPECTED_DEPLOYMENT_SURFACES.map(({ path }) => path),
      acceptedGovernanceBinding: 'compiled-plan-effectiveStatus-accepted',
      utf8CaseInsensitiveTokens: H047_SIGNAL_POLICY.patterns.map(({ source }) => source),
      archiveExpansionPolicyVersion: 'overlaykit-h047-archive-expansion/v1',
    };
    if (
      !exactObjectKeys(reviewMap, [
        'schemaVersion',
        'hypothesis',
        'subject',
        'signalPolicyVersion',
        'signalPolicy',
        'reviewStatus',
        'humanAcceptanceRef',
        'pendingHumanJudgments',
        'paths',
        'directCandidates',
        'conflicts',
      ]) ||
      reviewMap.hypothesis !== 'H-047' ||
      canonicalJson(reviewMap.subject) !== canonicalJson(H047_SUBJECT) ||
      reviewMap.signalPolicyVersion !== H047_SIGNAL_POLICY.version ||
      canonicalJson(reviewMap.signalPolicy) !== canonicalJson(expectedSignalPolicy) ||
      reviewMap.reviewStatus !== 'agent-proposed-pending-human-acceptance' ||
      reviewMap.humanAcceptanceRef !== null ||
      !Array.isArray(reviewMap.pendingHumanJudgments) ||
      reviewMap.pendingHumanJudgments.length === 0 ||
      new Set(reviewMap.pendingHumanJudgments).size !== reviewMap.pendingHumanJudgments.length ||
      reviewMap.pendingHumanJudgments.some((judgment) => !nonEmptyString(judgment)) ||
      !Array.isArray(reviewMap.paths) ||
      !Array.isArray(reviewMap.directCandidates) ||
      !Array.isArray(reviewMap.conflicts)
    ) {
      reviewShapeValid = false;
      mechanicalUnknowns.push({ code: 'semantic-review-map-invalid' });
    }
    if (reviewMap.humanAcceptanceRef === null) {
      humanUnknowns.push({
        code: 'human-review-not-accepted',
        reviewStatus: reviewMap.reviewStatus ?? null,
        humanAcceptanceRef: null,
      });
      for (const judgment of reviewMap.pendingHumanJudgments ?? []) {
        humanUnknowns.push({ code: 'pending-human-judgment', judgment });
      }
    }

    const archiveEntries = entries.filter(({ path }) => /\.(?:tar\.gz|tgz)$/iu.test(path));
    try {
      archiveForest = expandTarGzipForest(
        archiveEntries.map((entry) => ({
          path: entry.path,
          bytes: contentsByPath.get(entry.path),
        }))
      );
    } catch {
      mechanicalUnknowns.push({ code: 'archive-forest-reconstruction-failed' });
    }
    const archiveRootByPath = new Map(archiveForest.roots.map((root) => [root.rootPath, root]));
    const archiveRootBySha = new Map(archiveForest.roots.map((root) => [root.rootSha256, root]));

    if (reviewShapeValid) {
      const declaredPaths = reviewMap.paths.map(({ path }) => path);
      const expectedPaths = entries.map(({ path }) => path);
      if (
        reviewMap.paths.length !== entries.length ||
        new Set(declaredPaths).size !== declaredPaths.length ||
        canonicalJson(declaredPaths) !== canonicalJson(expectedPaths)
      ) {
        mechanicalUnknowns.push({ code: 'semantic-review-path-bijection-mismatch' });
      }
      for (const receipt of reviewMap.paths) {
        const entry = entryByPath.get(receipt?.path);
        const bytes = contentsByPath.get(receipt?.path);
        if (
          !exactObjectKeys(receipt, [
            'path',
            'mode',
            'gitOid',
            'byteLength',
            'blobSha256',
            'format',
            'signals',
            'review',
            'citations',
            'atoms',
            'outgoingEdges',
            'indirections',
          ]) ||
          entry === undefined ||
          !Buffer.isBuffer(bytes) ||
          receipt.mode !== entry.mode ||
          receipt.gitOid !== entry.oid ||
          receipt.byteLength !== entry.byteLength ||
          receipt.blobSha256 !== entry.sha256 ||
          receipt.format !== inferContentFormat(receipt.path) ||
          !Array.isArray(receipt.signals) ||
          !Array.isArray(receipt.citations) ||
          !Array.isArray(receipt.atoms) ||
          !Array.isArray(receipt.outgoingEdges) ||
          !exactObjectKeys(receipt.indirections, ['state', 'edgeIds', 'archiveExpansion']) ||
          !Array.isArray(receipt.indirections.edgeIds)
        ) {
          mechanicalUnknowns.push({
            code: 'semantic-path-receipt-invalid',
            path: receipt?.path ?? null,
          });
          continue;
        }
        receiptByPath.set(receipt.path, receipt);
        if (
          receipt.format === 'json' &&
          (() => {
            try {
              parseJsonBytes(bytes, receipt.path);
              return false;
            } catch {
              return true;
            }
          })()
        ) {
          mechanicalUnknowns.push({ code: 'semantic-json-format-invalid', path: receipt.path });
        } else if (
          receipt.format === 'yaml' &&
          (() => {
            try {
              parseYaml(new TextDecoder('utf-8', { fatal: true }).decode(bytes), {
                uniqueKeys: true,
              });
              return false;
            } catch {
              return true;
            }
          })()
        ) {
          mechanicalUnknowns.push({ code: 'semantic-yaml-format-invalid', path: receipt.path });
        } else if (receipt.format !== 'tar+gzip' && !scanSemanticSignals(bytes).utf8) {
          mechanicalUnknowns.push({ code: 'opaque-non-archive-path', path: receipt.path });
        }

        const acceptedGovernance =
          receipt.path === '.overlaykit/governance/plan.json' ||
          acceptedAuthorityPaths.has(receipt.path);
        const archiveRoot = archiveRootByPath.get(receipt.path);
        const signals = expectedSignals({
          bytes,
          path: receipt.path,
          blobSha256: receipt.blobSha256,
          acceptedGovernance,
          archiveExpansionRoles: archiveRoot?.expansion.semanticRoles ?? [],
          archiveOrigin: archiveRoot === undefined ? null : 'archive-expansion',
          archiveClosureSha256: archiveRoot?.expansion.closureSha256 ?? null,
        });
        const roles = signals.map(({ role }) => role);
        if (
          canonicalJson(receipt.signals) !== canonicalJson(signals) ||
          canonicalJson(receipt.review) !== canonicalJson(expectedReview(roles))
        ) {
          mechanicalUnknowns.push({ code: 'semantic-signal-review-mismatch', path: receipt.path });
        }
        const expectedIndirectionState =
          receipt.outgoingEdges.length > 0 || archiveRoot !== undefined ? 'closed' : 'none';
        if (
          receipt.indirections.state !== expectedIndirectionState ||
          canonicalJson(receipt.indirections.edgeIds) !==
            canonicalJson(receipt.outgoingEdges.map(({ id }) => id)) ||
          (archiveRoot === undefined) !== (receipt.indirections.archiveExpansion === null)
        ) {
          mechanicalUnknowns.push({
            code: 'semantic-indirection-state-mismatch',
            path: receipt.path,
          });
        }
        if (archiveRoot !== undefined) {
          try {
            validateArchiveExpansion({
              declared: receipt.indirections.archiveExpansion,
              root: archiveRoot,
              rootPath: receipt.path,
              archiveForest,
              archiveRootBySha,
            });
          } catch {
            mechanicalUnknowns.push({
              code: 'semantic-archive-expansion-mismatch',
              path: receipt.path,
            });
          }
        }
        if (roles.length > 0) {
          candidates.push({
            path: receipt.path,
            roles,
            agentDisposition: receipt.review.agentDisposition,
            humanDisposition: receipt.review.humanDisposition,
            citationIds: receipt.citations.map(({ id }) => id),
            atomIds: receipt.atoms.map(({ id }) => id),
            outgoingEdgeIds: receipt.outgoingEdges.map(({ id }) => id),
            indirectionState: receipt.indirections.state,
          });
        }
      }

      const expectedDirectCandidates = candidates.map(({ path, roles }) => ({ path, roles }));
      if (canonicalJson(reviewMap.directCandidates) !== canonicalJson(expectedDirectCandidates)) {
        mechanicalUnknowns.push({ code: 'semantic-direct-candidate-set-mismatch' });
      }
      if (reviewMap.conflicts.length > 0) {
        for (const conflict of reviewMap.conflicts) {
          mechanicalUnknowns.push({ code: 'semantic-review-conflict', conflict });
        }
      }

      for (const receipt of reviewMap.paths) {
        for (const citation of receipt.citations ?? []) {
          if (citationById.has(citation?.id)) {
            mechanicalUnknowns.push({
              code: 'semantic-duplicate-citation-id',
              id: citation?.id ?? null,
            });
            continue;
          }
          try {
            const validated = validateCitation(citation, {
              ownerPath: receipt.path,
              entryByPath,
              contentsByPath,
              archiveForest,
              archiveRootByPath,
            });
            citationById.set(validated.id, validated);
          } catch {
            mechanicalUnknowns.push({
              code: 'semantic-citation-invalid',
              id: citation?.id ?? null,
            });
          }
        }
      }
      const atomIds = new Set();
      for (const receipt of reviewMap.paths) {
        for (const atom of receipt.atoms ?? []) {
          if (atomIds.has(atom?.id)) {
            mechanicalUnknowns.push({ code: 'semantic-duplicate-atom-id', id: atom?.id ?? null });
            continue;
          }
          atomIds.add(atom?.id);
          try {
            validatedAtoms.push(
              validateAtom(atom, {
                ownerPath: receipt.path,
                citationById,
                acceptedAuthorityPaths,
              })
            );
          } catch (error) {
            mechanicalUnknowns.push({
              code: 'semantic-atom-invalid',
              id: atom?.id ?? null,
              detail: error.message,
            });
          }
        }
      }
      const edgeIds = new Set();
      for (const receipt of reviewMap.paths) {
        for (const edge of receipt.outgoingEdges ?? []) {
          if (edgeIds.has(edge?.id)) {
            mechanicalUnknowns.push({ code: 'semantic-duplicate-edge-id', id: edge?.id ?? null });
            continue;
          }
          edgeIds.add(edge?.id);
          try {
            validatedEdges.push(
              validateEdge(edge, {
                ownerPath: receipt.path,
                citationById,
                entryByPath,
                contentsByPath,
                archiveRootByPath,
              })
            );
          } catch (error) {
            mechanicalUnknowns.push({
              code: 'semantic-edge-invalid',
              id: edge?.id ?? null,
              detail: error.message,
            });
          }
        }
      }
      const declaredAtoms = reviewMap.paths.flatMap((receipt) => receipt.atoms ?? []);
      if (canonicalJson(declaredAtoms) !== canonicalJson(H047_EXPECTED_TYPED_ATOMS)) {
        mechanicalUnknowns.push({
          code: 'semantic-atom-closure-mismatch',
          expectedCount: H047_EXPECTED_TYPED_ATOMS.length,
          actualCount: declaredAtoms.length,
        });
      }
      const declaredEdgeClosure = reviewMap.paths.flatMap(({ path, outgoingEdges = [] }) =>
        outgoingEdges.map((edge) => ({ ownerPath: path, edge }))
      );
      const declaredEdgeClosureSha256 = sha256(canonicalJson(declaredEdgeClosure));
      if (
        declaredEdgeClosure.length !== H047_EXPECTED_TYPED_EDGE_COUNT ||
        declaredEdgeClosureSha256 !== H047_EXPECTED_TYPED_EDGE_CLOSURE_SHA256
      ) {
        mechanicalUnknowns.push({
          code: 'semantic-edge-closure-mismatch',
          expectedCount: H047_EXPECTED_TYPED_EDGE_COUNT,
          actualCount: declaredEdgeClosure.length,
          expectedSha256: H047_EXPECTED_TYPED_EDGE_CLOSURE_SHA256,
          actualSha256: declaredEdgeClosureSha256,
        });
      }
    }

    const chainReview = classifyTypedChains({
      atoms: validatedAtoms,
      edges: validatedEdges,
    });
    const reviewCoverageComplete = reviewShapeValid && mechanicalUnknowns.length === 0;
    const coverageComplete =
      reviewCoverageComplete &&
      humanUnknowns.length === 0 &&
      entries.every(({ available }) => available) &&
      entries.length === H047_SUBJECT.entryCount;
    unknowns.push(...humanUnknowns, ...mechanicalUnknowns);
    const authoritativeRecordReview = governanceRecords
      .filter((record) =>
        record.type === 'decision' || record.type === 'specification'
          ? bindingByPath.get(record.path)?.effectiveStatus === 'accepted'
          : record.status === 'implemented'
      )
      .map((record) => {
        const receipt = receiptByPath.get(record.path);
        return {
          ...record,
          role: candidateRole(record.path, roleStatusMap),
          authorityBinding: bindingByPath.get(record.path),
          reviewDisposition: receipt?.review.agentDisposition ?? 'unresolved',
          rationaleCode: receipt?.review.rationaleCode ?? null,
        };
      });
    const rootClosures = archiveForest.roots.map(({ rootPath, expansion }) => ({
      path: rootPath,
      closureSha256: expansion.closureSha256,
      immediateMemberCount: expansion.immediateMemberCount,
      recursiveMemberCount: expansion.recursiveMemberCount,
    }));
    const eligibleChains = chainReview.eligibleChains;
    return {
      sourceMap,
      governance: {
        counts: {
          decisions: statusCounts(decisions),
          specifications: statusCounts(specifications),
          changes: statusCounts(changes),
        },
        records: governanceRecords,
      },
      acceptedRecordReview: authoritativeRecordReview,
      targetOccurrences,
      targetOccurrencePathCounts,
      surfaces,
      semanticReview: {
        schemaVersion: reviewMap.schemaVersion,
        signalPolicyVersion: reviewMap.signalPolicyVersion,
        reviewStatus: reviewMap.reviewStatus,
        reviewMapSha256: sha256(canonicalJson(reviewMap)),
        humanAcceptanceRef: reviewMap.humanAcceptanceRef,
        pendingHumanJudgments: reviewMap.pendingHumanJudgments,
        pathCount: receiptByPath.size,
        directCandidateCount: candidates.length,
        archiveForest: {
          rootCount: archiveForest.roots.length,
          archiveOccurrences: archiveForest.observations.archives,
          memberOccurrences: archiveForest.observations.logicalMembers,
          decompressedBytes: archiveForest.observations.decompressedBytes,
          payloadBytes: archiveForest.observations.payloadBytes,
          rootClosures,
        },
        coverageComplete: reviewCoverageComplete,
      },
      candidates,
      chainComponents: chainReview.components,
      unknowns,
      eligibleChains,
      coverageComplete,
      outcome: deriveH047Outcome({ coverageComplete, unknowns, eligibleChains }),
    };
  }

  unknowns.push({ code: 'semantic-review-map-invalid' });
  const authoritativeRecordReview = governanceRecords
    .filter((record) =>
      record.type === 'decision' || record.type === 'specification'
        ? bindingByPath.get(record.path)?.effectiveStatus === 'accepted'
        : record.status === 'implemented'
    )
    .map((record) => ({
      ...record,
      role: candidateRole(record.path, roleStatusMap),
      authorityBinding: bindingByPath.get(record.path),
      reviewDisposition: 'unresolved',
      rationaleCode: 'semantic-review-map-invalid',
    }));
  const eligibleChains = [];
  const coverageComplete = false;

  return {
    sourceMap,
    governance: {
      counts: {
        decisions: statusCounts(decisions),
        specifications: statusCounts(specifications),
        changes: statusCounts(changes),
      },
      records: governanceRecords,
    },
    acceptedRecordReview: authoritativeRecordReview,
    targetOccurrences,
    targetOccurrencePathCounts,
    surfaces,
    semanticReview: {
      schemaVersion: reviewMap?.schemaVersion ?? null,
      signalPolicyVersion: reviewMap?.signalPolicyVersion ?? null,
      reviewStatus: reviewMap?.reviewStatus ?? null,
      reviewMapSha256:
        reviewMap && typeof reviewMap === 'object' ? sha256(canonicalJson(reviewMap)) : null,
      humanAcceptanceRef: reviewMap?.humanAcceptanceRef ?? null,
      pendingHumanJudgments: [],
      pathCount: 0,
      directCandidateCount: 0,
      archiveForest: {
        rootCount: 0,
        archiveOccurrences: 0,
        memberOccurrences: 0,
        decompressedBytes: 0,
        payloadBytes: 0,
        rootClosures: [],
      },
      coverageComplete: false,
    },
    candidates: [],
    chainComponents: [],
    unknowns,
    eligibleChains,
    coverageComplete,
    outcome: deriveH047Outcome({ coverageComplete, unknowns, eligibleChains }),
  };
}
