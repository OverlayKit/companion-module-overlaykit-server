import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const TAR_BLOCK_BYTES = 512;
const TAR_END_BYTES = TAR_BLOCK_BYTES * 2;
const DEFAULT_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_MEMBERS = 10_000;
const MAX_PATH_BYTES = 16 * 1024;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

export const H042_REPLAY_ARCHIVE_SHA256 =
  '15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36';
export const H042_EVIDENCE_SHA256 =
  'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88';
export const H042_RUN_ID = 'h042-2026-07-26T16-19-05-858Z-efaf85fa';
export const H042_REPLAY_ARCHIVE_RELATIVE_PATH = `evidence/h042/${H042_EVIDENCE_SHA256}/replay-${H042_REPLAY_ARCHIVE_SHA256}.tar.gz`;
export const H042_REPLAY_ARCHIVE_PATH = fileURLToPath(
  new URL(`../../${H042_REPLAY_ARCHIVE_RELATIVE_PATH}`, import.meta.url)
);
export const H042_RUN_MEMBER_PATH = `artifacts/h042/${H042_RUN_ID}/run.json`;
export const H042_VERIFICATION_MEMBER_PATH = `artifacts/h042/${H042_RUN_ID}/verification.json`;

function archiveError(message, options) {
  return new Error(`H-043 replay archive: ${message}`, options);
}

function asBuffer(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Buffer or Uint8Array`);
  }
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isZero(bytes) {
  for (const byte of bytes) {
    if (byte !== 0) return false;
  }
  return true;
}

function decodeUtf8(bytes, label) {
  try {
    return UTF8.decode(bytes);
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
    const bits = BigInt(bytes.length * 8 - 1);
    let value = BigInt(bytes[0] & 0x7f);
    for (const byte of bytes.subarray(1)) value = (value << 8n) | BigInt(byte);
    if ((bytes[0] & 0x40) !== 0) value -= 1n << bits;
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw archiveError(`${label} is outside the supported non-negative safe-integer range`);
    }
    return Number(value);
  }

  const text = bytes.toString('ascii').replace(/\0.*$/u, '').trim();
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

function parsePaxSize(value) {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw archiveError('PAX size is not a canonical non-negative decimal integer');
  }
  const size = BigInt(value);
  if (size > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw archiveError('PAX size exceeds the safe-integer range');
  }
  return Number(size);
}

function verifyHeader(header, offset) {
  const magic = header.subarray(257, 263);
  const legacy = isZero(magic);
  const ustar = magic.equals(Buffer.from('ustar\0', 'ascii'));
  const gnu = magic.equals(Buffer.from('ustar ', 'ascii'));
  if (!legacy && !ustar && !gnu) {
    throw archiveError(`header at byte ${offset} has an unsupported tar magic`);
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

function headerPath(header) {
  const name = decodeTarField(header.subarray(0, 100), 'header name');
  const prefix = decodeTarField(header.subarray(345, 500), 'header prefix');
  return prefix === '' ? name : `${prefix}/${name}`;
}

function validateMemberPath(rawPath, { directory = false } = {}) {
  if (typeof rawPath !== 'string' || rawPath === '') {
    throw archiveError('member path is empty');
  }
  if (Buffer.byteLength(rawPath, 'utf8') > MAX_PATH_BYTES) {
    throw archiveError('member path exceeds the supported length');
  }
  if (/[\u0000-\u001f\u007f]/u.test(rawPath)) {
    throw archiveError(`member path contains a control character: ${JSON.stringify(rawPath)}`);
  }
  if (rawPath.includes('\\')) {
    throw archiveError(`member path contains a backslash: ${JSON.stringify(rawPath)}`);
  }
  if (rawPath.startsWith('/') || /^[A-Za-z]:/u.test(rawPath)) {
    throw archiveError(`member path is absolute: ${JSON.stringify(rawPath)}`);
  }

  const path = directory ? rawPath.replace(/\/+$/u, '') : rawPath;
  if (!directory && rawPath.endsWith('/')) {
    throw archiveError(`regular member path ends with a slash: ${JSON.stringify(rawPath)}`);
  }
  const segments = path.split('/');
  if (
    path === '' ||
    segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw archiveError(
      `member path is not canonical repository-relative: ${JSON.stringify(rawPath)}`
    );
  }
  return path;
}

function parsePaxRecords(body, label) {
  const updates = new Map();
  let offset = 0;
  while (offset < body.length) {
    let space = offset;
    while (space < body.length && body[space] >= 0x30 && body[space] <= 0x39) space += 1;
    if (space === offset || body[space] !== 0x20) {
      throw archiveError(`${label} has a malformed record length`);
    }
    const lengthText = body.subarray(offset, space).toString('ascii');
    if (!/^[1-9][0-9]*$/u.test(lengthText)) {
      throw archiveError(`${label} has a non-canonical record length`);
    }
    const length = Number(lengthText);
    if (!Number.isSafeInteger(length) || length <= space - offset + 1) {
      throw archiveError(`${label} has an invalid record length`);
    }
    const end = offset + length;
    if (end > body.length || body[end - 1] !== 0x0a) {
      throw archiveError(`${label} has a truncated record`);
    }

    const payload = body.subarray(space + 1, end - 1);
    const equals = payload.indexOf(0x3d);
    if (equals <= 0) throw archiveError(`${label} has a record without a key/value pair`);
    const key = decodeUtf8(payload.subarray(0, equals), `${label} key`);
    const value = decodeUtf8(payload.subarray(equals + 1), `${label} value`);
    if (/[\u0000-\u001f\u007f=]/u.test(key)) {
      throw archiveError(`${label} has an invalid key`);
    }
    if (updates.has(key)) throw archiveError(`${label} repeats key ${JSON.stringify(key)}`);
    updates.set(key, value);
    offset = end;
  }
  return updates;
}

function applyPaxUpdates(attributes, updates) {
  for (const [key, value] of updates) {
    if (value === '') attributes.delete(key);
    else attributes.set(key, value);
  }
}

function parseGnuLongValue(body, label) {
  const nul = body.indexOf(0);
  if (nul === -1) throw archiveError(`${label} is missing its NUL terminator`);
  if (!isZero(body.subarray(nul))) {
    throw archiveError(`${label} has non-zero bytes after its NUL terminator`);
  }
  return decodeUtf8(body.subarray(0, nul), label);
}

function paddedSize(size) {
  return Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
}

/**
 * Decode one gzip-compressed tar archive without invoking a host archive utility.
 *
 * Only regular-file bytes are returned. Directory entries are admitted and
 * validated but omitted from the Map; link and special-file entries fail closed.
 */
export function readTarGzipMembers(
  archiveBytes,
  { maxDecompressedBytes = DEFAULT_MAX_DECOMPRESSED_BYTES, maxMembers = DEFAULT_MAX_MEMBERS } = {}
) {
  const compressed = asBuffer(archiveBytes, 'archiveBytes');
  if (!Number.isSafeInteger(maxDecompressedBytes) || maxDecompressedBytes < TAR_END_BYTES) {
    throw new TypeError('maxDecompressedBytes must be a safe integer of at least 1024');
  }
  if (!Number.isSafeInteger(maxMembers) || maxMembers < 1) {
    throw new TypeError('maxMembers must be a positive safe integer');
  }

  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: maxDecompressedBytes });
  } catch (error) {
    throw archiveError('gzip decoding failed', { cause: error });
  }
  if (tar.length % TAR_BLOCK_BYTES !== 0) {
    throw archiveError('decompressed tar length is not block-aligned');
  }

  const members = new Map();
  const seenPaths = new Set();
  const globalPax = new Map();
  let localPax = new Map();
  let pendingLongPath = null;
  let pendingLongLink = null;
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
      if (localPax.size > 0 || pendingLongPath !== null || pendingLongLink !== null) {
        throw archiveError('tar ends with metadata that has no following member');
      }
      return members;
    }

    verifyHeader(header, offset);
    const typeByte = header[156];
    const type = typeByte === 0 ? '0' : String.fromCharCode(typeByte);
    const declaredSize = parseTarNumber(header.subarray(124, 136), 'member size');
    const metadata = type === 'x' || type === 'g' || type === 'L' || type === 'K';
    const attributes = new Map(globalPax);
    applyPaxUpdates(attributes, localPax);
    const effectiveSize =
      !metadata && attributes.has('size') ? parsePaxSize(attributes.get('size')) : declaredSize;
    const dataOffset = offset + TAR_BLOCK_BYTES;
    const nextOffset = dataOffset + paddedSize(effectiveSize);
    if (nextOffset > tar.length || dataOffset + effectiveSize > tar.length) {
      throw archiveError(`member at byte ${offset} is truncated`);
    }
    const body = tar.subarray(dataOffset, dataOffset + effectiveSize);
    if (!isZero(tar.subarray(dataOffset + effectiveSize, nextOffset))) {
      throw archiveError(`member at byte ${offset} has non-zero padding`);
    }
    offset = nextOffset;

    if (type === 'x' || type === 'g') {
      const updates = parsePaxRecords(
        body,
        type === 'x' ? 'local PAX header' : 'global PAX header'
      );
      if (type === 'g') applyPaxUpdates(globalPax, updates);
      else applyPaxUpdates(localPax, updates);
      continue;
    }
    if (type === 'L') {
      if (pendingLongPath !== null) throw archiveError('tar repeats GNU long-name metadata');
      pendingLongPath = parseGnuLongValue(body, 'GNU long name');
      continue;
    }
    if (type === 'K') {
      if (pendingLongLink !== null) throw archiveError('tar repeats GNU long-link metadata');
      pendingLongLink = parseGnuLongValue(body, 'GNU long link');
      continue;
    }

    const paxPath = attributes.get('path');
    if (paxPath !== undefined && pendingLongPath !== null && paxPath !== pendingLongPath) {
      throw archiveError('PAX and GNU metadata disagree about the member path');
    }
    const rawPath = paxPath ?? pendingLongPath ?? headerPath(header);
    const directory = type === '5';
    const memberPath = validateMemberPath(rawPath, { directory });
    logicalMembers += 1;
    if (logicalMembers > maxMembers)
      throw archiveError('member count exceeds the configured limit');
    if (seenPaths.has(memberPath)) {
      throw archiveError(`duplicate member path ${JSON.stringify(memberPath)}`);
    }
    seenPaths.add(memberPath);

    if (type === '0') {
      if (pendingLongLink !== null || attributes.has('linkpath')) {
        throw archiveError(`regular member ${JSON.stringify(memberPath)} carries link metadata`);
      }
      members.set(memberPath, Buffer.from(body));
    } else if (type === '5') {
      if (effectiveSize !== 0) {
        throw archiveError(`directory member ${JSON.stringify(memberPath)} has data`);
      }
      if (pendingLongLink !== null || attributes.has('linkpath')) {
        throw archiveError(`directory member ${JSON.stringify(memberPath)} carries link metadata`);
      }
    } else {
      throw archiveError(
        `unsupported tar member type ${JSON.stringify(type)} for ${JSON.stringify(memberPath)}`
      );
    }

    localPax = new Map();
    pendingLongPath = null;
    pendingLongLink = null;
  }

  throw archiveError('tar is missing its two-block terminator');
}

export async function readH042ReplayArchive(archivePath = H042_REPLAY_ARCHIVE_PATH) {
  const archiveBytes = await readFile(archivePath);
  const digest = sha256(archiveBytes);
  if (digest !== H042_REPLAY_ARCHIVE_SHA256) {
    throw archiveError(`archive SHA-256 ${digest} does not match ${H042_REPLAY_ARCHIVE_SHA256}`);
  }
  return readTarGzipMembers(archiveBytes);
}
