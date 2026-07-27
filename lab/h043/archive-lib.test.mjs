import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import {
  H042_REPLAY_ARCHIVE_PATH,
  H042_RUN_ID,
  H042_RUN_MEMBER_PATH,
  H042_VERIFICATION_MEMBER_PATH,
  readH042ReplayArchive,
  readTarGzipMembers,
} from './archive-lib.mjs';

const H042_DIRECTORY = `artifacts/h042/${H042_RUN_ID}`;
const EXPECTED_MEMBERS = new Map([
  [H042_RUN_MEMBER_PATH, 'be39e69140f733e7f56e371f144b6e7b0cd43c05b7be6bfea9850c440679a7b6'],
  [
    H042_VERIFICATION_MEMBER_PATH,
    '0fc4f3cd7f78fe1184331a40f97874521d97d6f5c677a4829588a6dc676e6919',
  ],
  [
    `${H042_DIRECTORY}/runtime-poll.jsonl`,
    'bb683cc084f53ee5ed7d0d4787e551d166ab832d841edd15e25b620e2d86f7f3',
  ],
  [
    `${H042_DIRECTORY}/host-poll.jsonl`,
    '05eae3cf455f5f654ed912df8d89fb902f06e92001f1b29637414185ac361f1c',
  ],
  [
    `${H042_DIRECTORY}/logs-initial.txt`,
    '27534063c7d53c75a8b20f8b0a50c4b0ca01bd09763baab7716fc062e50263e6',
  ],
  [
    `${H042_DIRECTORY}/logs-absent.txt`,
    '0b62162131e526aa07efc175a626623e885e9965362f833936d2e494391a4abb',
  ],
  [
    `${H042_DIRECTORY}/logs-pre-signal.txt`,
    'f5375408668603381d24b9289b307636b86db462022fd5fedfd1726fbc9e5d8b',
  ],
  [
    `${H042_DIRECTORY}/logs-final.txt`,
    '7e5983e87da8d011a875849dafafddf0c2e9cb19bb00a34bbef12b49d7908622',
  ],
]);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function writeString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  assert.ok(bytes.length <= length);
  bytes.copy(header, offset);
}

function writeOctal(header, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, '0');
  writeString(header, offset, length, `${text}\0`);
}

function tarHeader({ name, prefix = '', size, type = '0' }) {
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeString(header, 257, 6, 'ustar\0');
  writeString(header, 263, 2, '00');
  writeString(header, 345, 155, prefix);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

function tarEntry({ name, prefix, type = '0', body = Buffer.alloc(0) }) {
  const bytes = Buffer.from(body);
  const padding = Buffer.alloc((512 - (bytes.length % 512)) % 512);
  return Buffer.concat([tarHeader({ name, prefix, size: bytes.length, type }), bytes, padding]);
}

function paxRecord(key, value) {
  const suffix = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(suffix) + 1;
  while (String(length).length + Buffer.byteLength(suffix) !== length) {
    length = String(length).length + Buffer.byteLength(suffix);
  }
  return `${length}${suffix}`;
}

function archive(entries, { terminator = Buffer.alloc(1024) } = {}) {
  return gzipSync(Buffer.concat([...entries, terminator]), { mtime: 0 });
}

test('extracts the exact accepted H-042 replay bytes without a host tar process', async () => {
  assert.equal(H042_REPLAY_ARCHIVE_PATH.endsWith('.tar.gz'), true);
  const members = await readH042ReplayArchive();
  assert.equal(members.size, 70);
  for (const [memberPath, expectedHash] of EXPECTED_MEMBERS) {
    assert.equal(members.has(memberPath), true, `${memberPath} is present`);
    assert.equal(sha256(members.get(memberPath)), expectedHash, memberPath);
  }
  assert.equal(JSON.parse(members.get(H042_RUN_MEMBER_PATH)).runId, H042_RUN_ID);
  assert.equal(JSON.parse(members.get(H042_VERIFICATION_MEMBER_PATH)).verified, true);
});

test('handles ustar prefixes, PAX paths, and GNU long names', () => {
  const paxPath = `pax/${'segment/'.repeat(14)}member.txt`;
  const gnuPath = `gnu/${'segment/'.repeat(14)}member.txt`;
  const members = readTarGzipMembers(
    archive([
      tarEntry({ name: 'member.txt', prefix: 'ustar/prefix', body: 'ustar' }),
      tarEntry({
        name: 'PaxHeader',
        type: 'x',
        body: paxRecord('path', paxPath),
      }),
      tarEntry({ name: 'placeholder', body: 'pax' }),
      tarEntry({
        name: '././@LongLink',
        type: 'L',
        body: Buffer.from(`${gnuPath}\0`),
      }),
      tarEntry({ name: 'placeholder', body: 'gnu' }),
    ])
  );

  assert.equal(members.get('ustar/prefix/member.txt').toString(), 'ustar');
  assert.equal(members.get(paxPath).toString(), 'pax');
  assert.equal(members.get(gnuPath).toString(), 'gnu');
});

test('rejects duplicate and non-canonical member paths', () => {
  assert.throws(
    () =>
      readTarGzipMembers(
        archive([
          tarEntry({ name: 'duplicate.txt', body: 'first' }),
          tarEntry({ name: 'duplicate.txt', body: 'second' }),
        ])
      ),
    /duplicate member path/u
  );
  for (const name of ['../escape', '/absolute', './relative', 'nested//empty', 'C:drive']) {
    assert.throws(
      () => readTarGzipMembers(archive([tarEntry({ name, body: 'unsafe' })])),
      /member path/u,
      name
    );
  }
});

test('rejects truncated archives and dangling or truncated path metadata', () => {
  assert.throws(
    () =>
      readTarGzipMembers(
        archive([tarEntry({ name: 'member.txt', body: 'content' })], {
          terminator: Buffer.alloc(512),
        })
      ),
    /terminator is truncated/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        archive([
          tarEntry({
            name: '././@LongLink',
            type: 'L',
            body: Buffer.from('unterminated'),
          }),
        ])
      ),
    /missing its NUL terminator/u
  );
  assert.throws(
    () =>
      readTarGzipMembers(
        archive([
          tarEntry({
            name: 'PaxHeader',
            type: 'x',
            body: Buffer.from('24 path=truncated.txt\n'),
          }),
        ])
      ),
    /truncated record/u
  );
});
