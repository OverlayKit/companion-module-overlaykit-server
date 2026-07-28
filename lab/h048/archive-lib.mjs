import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

const TAR_BLOCK_BYTES = 512;
const TAR_END_BYTES = TAR_BLOCK_BYTES * 2;
const DEFAULT_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_ARCHIVE_MEMBERS = 256;
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });

export const H048_ARCHIVE_LIMITS = Object.freeze({
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

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value, new Set()));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function archiveError(message, options) {
  return new Error(`H-048 archive: ${message}`, options);
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
  if (!/^[0-7]+$/u.test(text)) {
    throw archiveError(`${label} is not a valid octal number`);
  }
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
  if (rawPath.endsWith('/')) {
    throw archiveError(`regular member path ends with a slash: ${JSON.stringify(rawPath)}`);
  }
  const segments = rawPath.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw archiveError(
      `member path is not canonical repository-relative: ${JSON.stringify(rawPath)}`
    );
  }
  return rawPath;
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
    if (error instanceof Error && error.message.startsWith('H-048 archive:')) {
      throw error;
    }
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
    const tarMode = parseTarNumber(header.subarray(100, 108), 'member mode', { allowEmpty: false });
    const mode = tarMode === 0o644 ? '100644' : tarMode === 0o755 ? '100755' : null;
    if (mode === null) {
      throw archiveError(`member at byte ${offset} has unsupported mode ${tarMode.toString(8)}`);
    }
    const declaredSize = parseTarNumber(header.subarray(124, 136), 'member size', {
      allowEmpty: false,
    });
    if (declaredSize > maxMemberBytes) {
      throw archiveError(`member at byte ${offset} exceeds the per-member size limit`);
    }
    const dataOffset = offset + TAR_BLOCK_BYTES;
    const nextOffset = dataOffset + paddedTarSize(declaredSize);
    if (nextOffset > tar.length || dataOffset + declaredSize > tar.length) {
      throw archiveError(`member at byte ${offset} is truncated`);
    }
    const body = tar.subarray(dataOffset, dataOffset + declaredSize);
    if (!isZero(tar.subarray(dataOffset + declaredSize, nextOffset))) {
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

function isArchiveMemberPath(memberPath) {
  return /\.(?:tar\.gz|tgz)$/iu.test(memberPath);
}

function isGzipBytes(bytes) {
  return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

function archiveLimit(options, name) {
  const value = options[name] ?? H048_ARCHIVE_LIMITS[name];
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
    (name) => !Object.prototype.hasOwnProperty.call(H048_ARCHIVE_LIMITS, name)
  );
  if (unknownOptions.length > 0) {
    throw new TypeError(`unknown archive limit: ${unknownOptions.sort().join(', ')}`);
  }
  const limits = Object.fromEntries(
    Object.keys(H048_ARCHIVE_LIMITS).map((name) => [name, archiveLimit(options, name)])
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
      if (rootPaths.has(root.path)) {
        throw new Error(`duplicate archive root: ${root.path}`);
      }
      rootPaths.add(root.path);
      return {
        path: root.path,
        bytes: asBuffer(root.bytes, `${root.path} bytes`),
      };
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
    if (depth > limits.maxDepth) {
      throw archiveError('nested archive depth exceeds the limit');
    }
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
      } else {
        recursivePayloadBytes += record.byteLength;
      }
      physicalMembers.push({
        path: record.path,
        type: 'file',
        mode: record.mode,
        byteLength: record.byteLength,
        sha256: record.sha256,
        nestedArchiveRef,
      });
    }
    const totalUncompressedBytes = physicalMembers.reduce(
      (sum, member) => sum + member.byteLength,
      0
    );
    const closureSha256 = archiveClosureSha256(physicalMembers);
    Object.assign(archiveReceipt, {
      closureSha256,
      recursiveMemberCount,
      totalUncompressedBytes,
      recursivePayloadBytes,
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
