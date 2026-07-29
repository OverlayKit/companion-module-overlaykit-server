import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  FailurePreservationVerificationError,
  buildReplayArchive,
  verifierConstants,
  verifyReplay,
  verifyTerminal,
} from './verify.mjs';

const SUBJECT_BYTES = Buffer.from(
  'ewogICJzY2hlbWFWZXJzaW9uIjogIm92ZXJsYXlraXQtbm9kZTIyLWZhaWx1cmUtcHJlc2VydmF0aW9uLXByZWZsaWdodC1zdWJqZWN0L3YxIiwKICAic3R1ZHkiOiAiTk9ERTIyLUZBSUxVUkUtUFJFU0VSVkFUSU9OLVBSRUZMSUdIVC0wMDEiLAogICJoeXBvdGhlc2lzIjogIkEgc3ludGhldGljLW9ubHkgc3VjY2Vzc29yIGFwcGFyYXR1cyBjYW4gcmVzZXJ2ZSBiZWZvcmUgYXR0ZW1wdGluZyBhbmQgcHJlc2VydmUgb25lIGRldGVybWluaXN0aWMgY29udGVudC1hZGRyZXNzZWQgcmVwbGF5YWJsZSB0ZXJtaW5hbCBlbnZlbG9wZSBmb3IgZWFjaCBvZiBsYXVuY2gtZmFpbHVyZSwgbWFsZm9ybWVkLW91dHB1dCwgZGl2ZXJnZW50LWF0dGVtcHRzLCBleGFjdC1pbmNvbXBhdGliaWxpdHksIGFuZCBzdWNjZXNzIGJlZm9yZSBzZW1hbnRpYyB2YWxpZGF0aW9uLCB3aXRob3V0IHJlYWRpbmcgcmVhbCBzb3VyY2VzIG9yIGNyZWF0aW5nIGF1dGhvcml0eS4iLAogICJub3JtYXRpdmUiOiBmYWxzZSwKICAic3ludGhldGljT25seSI6IHRydWUsCiAgInJlYWxTb3VyY2VFeGVjdXRpb24iOiBmYWxzZSwKICAicGF5bG9hZEFjcXVpc2l0aW9uIjogZmFsc2UsCiAgImgwNTVPcGVuZWQiOiBmYWxzZSwKICAiYXV0aG9yaXR5IjogIm5vbmUiLAogICJhY3Rpb24iOiBudWxsLAogICJhZ2VudElkZW50aXR5IjogewogICAgImFnZW50IjogIkNvZGV4IC9yb290IiwKICAgICJodW1hblByaW5jaXBhbCI6ICJAcm9kcmlnb3RlYW14IgogIH0sCiAgInNvdXJjZUFuY2hvciI6IHsKICAgICJtYWluQ29tbWl0IjogImQxY2FhM2JmZjFiNDdiNjFjNjYxZTRlYzQ1ODJhZGQ0ZjljNzk1YzMiLAogICAgIm1haW5UcmVlIjogImQ4M2ZhMTRhM2MyNTE4OTI2MDkyMWEwYzA4ODYyZTY1NDBhNTJiYWYiLAogICAgInBsYW5SYXdTaGEyNTYiOiAiMmM2M2ZiY2IyZTVkNWM0YTc2MzA4MGFjMTc0NzgzNTgyOTYwZWRiNzBhNDhiMjlhOTdiMDAwYzVhZmYwZjI0MyIsCiAgICAicGxhbkhhc2giOiAiYmFlNGRhZDE4ZWY3MGU1NGU1YTZjMGYyODEwOWQyMGIyN2RlMDg0MGNkMGM5NGQ4NmE5MzgxYjQ1MjE2OTllNCIsCiAgICAicHJvZmlsZUhhc2giOiAiOWI1NWMwMzRjMTZhNjUzZDQ5NzY3MjM3NGMxMmQ5NGY2ZjYwOWM3N2YyM2FlY2QwZjBkNDM3ZTIzMGNiNGViZCIsCiAgICAicHJlZGVjZXNzb3JNYW5pZmVzdFJhd1NoYTI1NiI6ICJkYzI2NjY0MThiMjczZDc1MmYzZjlkMDZlYmUzNTQ1MTVkYWQ1ZWIwNmVjNWQxYWE1OTc3MzI4MDZiZjJiNDY1IiwKICAgICJwcmVkZWNlc3Nvck1hbmlmZXN0Q29udGVudEhhc2giOiAiZWZhMDEwYTVjMjY4ZGNhOGIzNjRkMGVmZTY2OWY4MzE1ZDQxNWFkMTllYWQ5NWI3NWU4YjE1NWQ2NjRkOTJhMSIsCiAgICAiY2hnMDAzNlJhd1NoYTI1NiI6ICIyZmY4OGQ5NGQ4NzY4YjIzNTQ4ZTY0ZDA2NjkyMmFlYzNlMWQwYjhiYTdhYWFiMjc5MDdmOGFmMDQzMmJmNDkyIiwKICAgICJjaGcwMDM4UmF3U2hhMjU2IjogIjNiMGEyZmIzZGZiZmEwOGQ1OWRmODgxZGY1ZjA5N2JmNjY3NThlYjY1NjNlMjIzMDEyZjc5MGFhYThjOGQ3N2UiLAogICAgImNoZzAwMzlSYXdTaGEyNTYiOiAiNmQwNjJkNGExYWEyMzZkNDQxNDgxODQ1NTQ5YmVhNjVkM2EyYjNiMTE0OThiMzQzNjFiOWExOGM0YTZkNWE4NSIsCiAgICAiYmxvY2tpbmdSdW5uZXJSYXdTaGEyNTYiOiAiNWM1YmQyYjczNTAwYzk4Nzc5ZThiMGZlYThiOWQxNDlmN2Q2NjgxNWVmNjAxYTJiZDU5NDRiNTRmOGJmNDU3YiIKICB9LAogICJ0ZXJtaW5hbFBhcnRpdGlvbiI6IHsKICAgICJwcmVjZWRlbmNlIjogWwogICAgICAibGF1bmNoLWZhaWx1cmUiLAogICAgICAibWFsZm9ybWVkLW91dHB1dCIsCiAgICAgICJkaXZlcmdlbnQtYXR0ZW1wdHMiLAogICAgICAiZXhhY3QtaW5jb21wYXRpYmlsaXR5IiwKICAgICAgInN1Y2Nlc3MiCiAgICBdLAogICAgImV4cGVjdGVkQ2FzZUNvdW50IjogNSwKICAgICJleGFjdGx5T25lVGVybWluYWxQZXJDYXNlIjogdHJ1ZSwKICAgICJzY29wZSI6ICJ0aGUgZXhhY3Qgc2VhbGVkIHN5bnRoZXRpYyBmaXh0dXJlIG9ubHkiCiAgfSwKICAicGVyc2lzdGVuY2VQb2xpY3kiOiB7CiAgICAiZXZpZGVuY2VSb290IjogImFydGlmYWN0cy9ub2RlMjItZmFpbHVyZS1wcmVzZXJ2YXRpb24tcHJlZmxpZ2h0IiwKICAgICJnaXRpZ25vcmVMb2NhdG9yIjogIi5naXRpZ25vcmUiLAogICAgImdpdGlnbm9yZVJhd1NoYTI1NiI6ICIyYzQyNTAzODM0ZTYxZGVmM2JmNTg0MGI1YzU1M2E3M2IyZDU2OWNlZTczMmM2OWU3NDIwZjc1Y2U1ZTZmMWZjIiwKICAgICJyZXNlcnZhdGlvbkJlZm9yZUF0dGVtcHQiOiB0cnVlLAogICAgImV4Y2x1c2l2ZUNyZWF0ZSI6IHRydWUsCiAgICAibm9Gb2xsb3ciOiB0cnVlLAogICAgImRpcmVjdG9yeU1vZGUiOiAiMDcwMCIsCiAgICAiZmlsZU1vZGUiOiAiMDYwMCIsCiAgICAicmVndWxhckZpbGVMaW5rQ291bnQiOiAxLAogICAgInJlcGxheUZvcm1hdCI6ICJQT1NJWC11c3RhciIsCiAgICAiY2xvY2tQaWRSYW5kb21Mb2NhbGVBbmRBYnNvbHV0ZVJvb3RFeGNsdWRlZCI6IHRydWUKICB9LAogICJvdXRjb21lUG9saWN5IjogewogICAgInN1cHBvcnRlZE9ubHlJZiI6ICJhbGwgZml2ZSB0ZXJtaW5hbCBicmFuY2hlcyBhcmUgcHJlc2VydmVkIGFuZCBpbmRlcGVuZGVudGx5IHJlY29uc3RydWN0ZWQgYW5kIGV2ZXJ5IG5vbWluYXRlZCBjb250cm9sIHJlamVjdHMgb3IgcHJvdmVzIGRldGVybWluaXN0aWMgZXF1YWxpdHkiLAogICAgInJlZnV0ZWRPbmx5SWYiOiAidGhlIG5vbWluYXRlZCBib3VuZGFyeSBpcyBjbG9zZWQgYW5kIGF0IGxlYXN0IG9uZSB0ZXJtaW5hbCBicmFuY2ggaXMgbm90IHJlcHJlc2VudGFibGUiLAogICAgImluY29uY2x1c2l2ZUlmIjogImFueSByZXF1aXJlZCBzb3VyY2UsIGJyYW5jaCwgY29udHJvbCwgYXJ0aWZhY3QsIG9yIGludGVycHJldGF0aW9uIGlzIG9taXR0ZWQsIG9wYXF1ZSwgb3IgYW1iaWd1b3VzIiwKICAgICJpbnZhbGlkSWYiOiAiaW50ZWdyaXR5LCBzY29wZSwgYXV0aG9yaXR5LCByZXNlcnZhdGlvbi1vcmRlcmluZywgb3IgZXZpZGVuY2UtcHJlc2VydmF0aW9uIHJ1bGVzIGFyZSBicmVhY2hlZCIsCiAgICAiaHVtYW5SZXZpZXdSZXF1aXJlZCI6IHRydWUKICB9LAogICJjb250cm9scyI6IFsKICAgICJwYXJ0aWFsLXdyaXRlIiwKICAgICJkdXBsaWNhdGUtcmVzZXJ2YXRpb24iLAogICAgInN0YWxlbmVzcyIsCiAgICAiY29sbGlzaW9uIiwKICAgICJzeW1saW5rIiwKICAgICJoYXJkbGluayIsCiAgICAiY29udGFpbm1lbnQiLAogICAgImRpcmVjdG9yeS1wZXJtaXNzaW9uIiwKICAgICJmaWxlLW1vZGUiLAogICAgImRldGVybWluaXNtIgogIF0sCiAgImtub3duTGltaXRzIjogWwogICAgIlRoZSBwYXJ0aWFsLXdyaXRlIGNvbnRyb2wgaXMgYW4gaW5qZWN0ZWQgcmVjb3ZlcmFiaWxpdHkgYW5kIHJlamVjdGlvbiB0ZXN0LCBub3QgYSB1bml2ZXJzYWwgcG93ZXItbG9zcyBvciBzdG9yYWdlLWR1cmFiaWxpdHkgY2xhaW0uIiwKICAgICJSZWFsIHNvdXJjZSBleHBlY3RhdGlvbnMgYW5kIGltbXV0YWJsZSBwYXlsb2FkIGF1dGhvcml0eSByZW1haW4gYWJzZW50LiIsCiAgICAiUnVudGltZSB0cmFjaW5nLCBlZmZlY3RpdmUgc2VjY29tcCwgbGF0ZS1sb2FkZWQgb2JqZWN0cywgbG9hZGVyIHN0YXRlLCBrZXJuZWwgc3RhdGUsIGFuZCBUT0NUT1UgY2xvc3VyZSByZW1haW4gb3V0c2lkZSB0aGlzIGFwcGFyYXR1cy4iLAogICAgIlRoZSBhcHBhcmF0dXMgc291cmNlIGlzIG5vdCBHaXQtYW5jaG9yZWQgYnkgdGhpcyBhdXRob3JpemF0aW9uIGFuZCByZXF1aXJlcyBzZXBhcmF0ZSBodW1hbiByZXZpZXcgYmVmb3JlIGFueSBwdWJsaWNhdGlvbi4iCiAgXSwKICAicHJvaGliaXRlZCI6IFsKICAgICJyZWFsLXNvdXJjZSBleGVjdXRpb24gb3Igb2JzZXJ2YXRpb24iLAogICAgInBheWxvYWQgYWNxdWlzaXRpb24gb3IgcHJlc2VydmF0aW9uIiwKICAgICJILTA1NSBjcmVhdGlvbiBvciBleGVjdXRpb24iLAogICAgIm5ldHdvcmsgb3IgbGl2ZSBvYnNlcnZhdGlvbiIsCiAgICAiVVNCIG9yIGhpZHJhdyBhY2Nlc3MiLAogICAgIkRvY2tlciIsCiAgICAicHJvZHVjdCwgcHJvZmlsZSwgc2NoZW1hLCBjb21waWxlciwgcGxhbiwgY29uZmlndXJhdGlvbiwgQURSLCBvciBTUEVDIG11dGF0aW9uIiwKICAgICJjb21taXQsIHB1c2gsIG1lcmdlLCBvciBwdWJsaWNhdGlvbiIKICBdCn0K',
  'base64'
);

const SUBJECT = JSON.parse(SUBJECT_BYTES.toString('utf8'));
const EMPTY_BYTES = Buffer.alloc(0);
const EXPECTED_OUTPUT = Buffer.from(
  '{"compatibility":"compatible","marker":"node22-failure-preservation-v1"}\n',
  'utf8'
);
const INCOMPATIBLE_OUTPUT = Buffer.from(
  '{"compatibility":"incompatible","marker":"node22-failure-preservation-v1"}\n',
  'utf8'
);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function artifact(value) {
  return Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8');
}

function binary(bytes) {
  return {
    base64: bytes.toString('base64'),
    byteLength: bytes.byteLength,
    sha256: sha256(bytes),
  };
}

function attempt(ordinal, stdout, { exitCode = 0, signal = null, stderr = EMPTY_BYTES } = {}) {
  return {
    exitCode,
    ordinal: ordinal + 1,
    signal,
    stderr: binary(stderr),
    stdout: binary(stdout),
  };
}

function reservationFor(branchId) {
  const index = verifierConstants.branches.indexOf(branchId);
  assert.notEqual(index, -1);
  const document = {
    action: null,
    authority: 'none',
    branchId,
    normative: false,
    ordinal: index + 1,
    schemaVersion: 'overlaykit-node22-failure-preservation-preflight-reservation/v1',
    sourceAnchor: structuredClone(SUBJECT.sourceAnchor),
    study: verifierConstants.study,
    subjectRawSha256: verifierConstants.subjectRawSha256,
    synthetic: true,
  };
  return { bytes: artifact(document), document };
}

function branchInput(branchId) {
  if (branchId === 'launch-failure') {
    return {
      attempts: [],
      launchError: { code: 'ENOENT', syscall: 'spawn' },
    };
  }
  if (branchId === 'malformed-output') {
    return {
      attempts: [attempt(0, Buffer.from([0xff]))],
      launchError: null,
    };
  }
  if (branchId === 'divergent-attempts') {
    return {
      attempts: [attempt(0, EXPECTED_OUTPUT), attempt(1, INCOMPATIBLE_OUTPUT)],
      launchError: null,
    };
  }
  if (branchId === 'exact-incompatibility') {
    return {
      attempts: [attempt(0, INCOMPATIBLE_OUTPUT), attempt(1, INCOMPATIBLE_OUTPUT)],
      launchError: null,
    };
  }
  return {
    attempts: [attempt(0, EXPECTED_OUTPUT), attempt(1, EXPECTED_OUTPUT)],
    launchError: null,
  };
}

function terminalFor(branchId, reservationBytes, override = {}) {
  const ordinal = verifierConstants.branches.indexOf(branchId) + 1;
  const body = {
    action: null,
    attempts: branchInput(branchId).attempts,
    authority: 'none',
    branchId,
    launchError: branchInput(branchId).launchError,
    normative: false,
    ordinal,
    reservationRawSha256: sha256(reservationBytes),
    schemaVersion: 'overlaykit-node22-failure-preservation-preflight-terminal/v1',
    study: verifierConstants.study,
    synthetic: true,
    ...override,
  };
  const document = { ...body, semanticSha256: canonicalHash(body) };
  return { bytes: artifact(document), document };
}

function refreshTerminal(document) {
  const body = structuredClone(document);
  delete body.semanticSha256;
  return artifact({ ...body, semanticSha256: canonicalHash(body) });
}

function expectCode(callback, code) {
  assert.throws(
    callback,
    (error) => error instanceof FailurePreservationVerificationError && error.code === code,
    code
  );
}

function fixtureFor(branchId) {
  const reservation = reservationFor(branchId);
  const terminal = terminalFor(branchId, reservation.bytes);
  return { reservation, terminal };
}

function rewriteHeaderChecksum(archive, offset = 0) {
  archive.fill(0x20, offset + 148, offset + 156);
  let checksum = 0;
  for (const byte of archive.subarray(offset, offset + 512)) checksum += byte;
  Buffer.from(`${checksum.toString(8).padStart(6, '0')}\0 `, 'ascii').copy(archive, offset + 148);
}

test('local subject literal is the exact pinned untracked subject', () => {
  assert.equal(sha256(SUBJECT_BYTES), verifierConstants.subjectRawSha256);
});

test('independently derives all five terminal branches and exact reason codes', () => {
  const expectedCounts = [0, 1, 2, 2, 2];
  for (const [ordinal, branchId] of verifierConstants.branches.entries()) {
    const { reservation, terminal } = fixtureFor(branchId);
    const receipt = verifyTerminal({
      subjectBytes: SUBJECT_BYTES,
      reservationBytes: reservation.bytes,
      terminalBytes: terminal.bytes,
    });
    assert.equal(receipt.branchId, branchId);
    assert.equal(receipt.reasonCode, verifierConstants.reasonCodes[branchId]);
    assert.equal(receipt.attemptCount, expectedCounts[ordinal]);
    assert.equal(receipt.authority, 'none');
    assert.equal(receipt.action, null);
  }
});

test('malformed precedence includes invalid UTF-8, invalid JSON, noncanonical JSON, and bad process receipts', () => {
  const cases = [
    attempt(0, Buffer.from([0xff])),
    attempt(0, Buffer.from('{', 'utf8')),
    attempt(0, Buffer.from('{ "compatibility": "compatible" }', 'utf8')),
    attempt(0, EXPECTED_OUTPUT, { exitCode: 1 }),
    attempt(0, EXPECTED_OUTPUT, { signal: 'SIGTERM' }),
    attempt(0, EXPECTED_OUTPUT, { stderr: Buffer.from('diagnostic', 'utf8') }),
  ];
  for (const value of cases) {
    const reservation = reservationFor('malformed-output');
    const terminal = terminalFor('malformed-output', reservation.bytes, {
      attempts: [value],
    });
    assert.equal(
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
      }).reasonCode,
      'synthetic-output-malformed'
    );
  }
});

test('coherently rehashed semantic mutations reach declared-branch rejection', () => {
  const { reservation, terminal } = fixtureFor('success');
  const mutated = structuredClone(terminal.document);
  mutated.attempts = [attempt(0, INCOMPATIBLE_OUTPUT), attempt(1, INCOMPATIBLE_OUTPUT)];
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: refreshTerminal(mutated),
      }),
    'declared-branch-mismatch'
  );
});

test('subject, source-anchor, reservation, semantic, authority, and shape drift fail closed', () => {
  const { reservation, terminal } = fixtureFor('success');

  const subjectDrift = Buffer.from(SUBJECT_BYTES);
  subjectDrift[10] ^= 1;
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: subjectDrift,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
      }),
    'subject-raw-sha256-mismatch'
  );

  const staleReservation = structuredClone(reservation.document);
  staleReservation.sourceAnchor.planHash = 'f'.repeat(64);
  const staleReservationBytes = artifact(staleReservation);
  const reboundTerminal = terminalFor('success', staleReservationBytes);
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: staleReservationBytes,
        terminalBytes: reboundTerminal.bytes,
      }),
    'reservation-source-anchor-mismatch'
  );

  const reservationMismatch = structuredClone(terminal.document);
  reservationMismatch.reservationRawSha256 = 'f'.repeat(64);
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: refreshTerminal(reservationMismatch),
      }),
    'reservation-raw-sha256-mismatch'
  );

  const semanticDrift = structuredClone(terminal.document);
  semanticDrift.semanticSha256 = 'f'.repeat(64);
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: artifact(semanticDrift),
      }),
    'terminal-semantic-sha256-mismatch'
  );

  const authority = structuredClone(terminal.document);
  authority.authority = 'verifier';
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: refreshTerminal(authority),
      }),
    'authority-overclaim'
  );

  const extra = structuredClone(terminal.document);
  extra.verdict = 'supported';
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: refreshTerminal(extra),
      }),
    'terminal-shape-invalid'
  );
});

test('binary envelopes reject noncanonical base64, length drift, and digest drift', () => {
  const cases = [
    ['binary-base64-invalid', (value) => (value.base64 = '====')],
    ['binary-byte-length-mismatch', (value) => (value.byteLength += 1)],
    ['binary-sha256-mismatch', (value) => (value.sha256 = 'f'.repeat(64))],
  ];
  for (const [code, mutate] of cases) {
    const { reservation, terminal } = fixtureFor('success');
    const changed = structuredClone(terminal.document);
    mutate(changed.attempts[0].stdout);
    expectCode(
      () =>
        verifyTerminal({
          subjectBytes: SUBJECT_BYTES,
          reservationBytes: reservation.bytes,
          terminalBytes: refreshTerminal(changed),
        }),
      code
    );
  }
});

test('terminal branch cardinalities and launch-error shape are exact', () => {
  const malformed = fixtureFor('malformed-output');
  const tooMany = structuredClone(malformed.terminal.document);
  tooMany.attempts.push(attempt(1, Buffer.from([0xff])));
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: malformed.reservation.bytes,
        terminalBytes: refreshTerminal(tooMany),
      }),
    'terminal-attempt-cardinality-invalid'
  );

  const launch = fixtureFor('launch-failure');
  const badLaunch = structuredClone(launch.terminal.document);
  badLaunch.launchError.extra = true;
  expectCode(
    () =>
      verifyTerminal({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: launch.reservation.bytes,
        terminalBytes: refreshTerminal(badLaunch),
      }),
    'terminal-shape-invalid'
  );
});

test('POSIX-ustar replay is sorted, deterministic, exact, and independently verified', () => {
  const { reservation, terminal } = fixtureFor('success');
  const left = buildReplayArchive([
    { archivePath: 'terminal.json', bytes: terminal.bytes },
    { archivePath: 'reservation.json', bytes: reservation.bytes },
  ]);
  const right = buildReplayArchive([
    { archivePath: 'reservation.json', bytes: reservation.bytes },
    { archivePath: 'terminal.json', bytes: terminal.bytes },
  ]);
  assert.deepEqual(left, right);

  const receipt = verifyReplay({
    subjectBytes: SUBJECT_BYTES,
    reservationBytes: reservation.bytes,
    terminalBytes: terminal.bytes,
    archiveBytes: left,
  });
  assert.equal(receipt.branchId, 'success');
  assert.equal(receipt.archiveMemberCount, 2);
  assert.equal(receipt.archiveRawSha256, sha256(left));
  assert.equal(receipt.archiveSha256, sha256(left));
  assert.equal(receipt.replayVerification, 'byte-identical-posix-ustar-reconstruction');
  assert.equal(receipt.status, 'replay-reconstructed');
});

test('replay rejects truncation, checksum drift, metadata drift, and extra terminators', () => {
  const { reservation, terminal } = fixtureFor('success');
  const archive = buildReplayArchive([
    { archivePath: 'reservation.json', bytes: reservation.bytes },
    { archivePath: 'terminal.json', bytes: terminal.bytes },
  ]);

  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: archive.subarray(0, archive.length - 1),
      }),
    'replay-truncated'
  );

  const checksum = Buffer.from(archive);
  checksum[0] ^= 1;
  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: checksum,
      }),
    'replay-checksum-invalid'
  );

  const metadata = Buffer.from(archive);
  Buffer.from('0000644\0', 'ascii').copy(metadata, 100);
  rewriteHeaderChecksum(metadata);
  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: metadata,
      }),
    'replay-metadata-invalid'
  );

  const extraTerminator = Buffer.concat([archive, Buffer.alloc(512)]);
  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: extraTerminator,
      }),
    'replay-terminator-invalid'
  );
});

test('replay rejects unsafe paths, member collision, wrong roster, and rebound bytes', () => {
  const { reservation, terminal } = fixtureFor('success');
  for (const archivePath of [
    '../reservation.json',
    '/reservation.json',
    'C:/reservation.json',
    'a\\b',
  ]) {
    expectCode(
      () => buildReplayArchive([{ archivePath, bytes: reservation.bytes }]),
      'replay-path-invalid'
    );
  }
  expectCode(
    () =>
      buildReplayArchive([
        { archivePath: 'reservation.json', bytes: reservation.bytes },
        { archivePath: 'reservation.json', bytes: terminal.bytes },
      ]),
    'replay-member-collision'
  );

  const wrongRoster = buildReplayArchive([
    { archivePath: 'reservation.json', bytes: reservation.bytes },
  ]);
  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: wrongRoster,
      }),
    'replay-member-roster-invalid'
  );

  const rebound = buildReplayArchive([
    { archivePath: 'reservation.json', bytes: terminal.bytes },
    { archivePath: 'terminal.json', bytes: terminal.bytes },
  ]);
  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: rebound,
      }),
    'replay-member-bytes-mismatch'
  );
});

test('noncanonical but parseable tar metadata is rejected as nondeterministic', () => {
  const { reservation, terminal } = fixtureFor('success');
  const archive = buildReplayArchive([
    { archivePath: 'reservation.json', bytes: reservation.bytes },
    { archivePath: 'terminal.json', bytes: terminal.bytes },
  ]);
  const changed = Buffer.from(archive);
  changed[336] = 0x20;
  rewriteHeaderChecksum(changed);
  expectCode(
    () =>
      verifyReplay({
        subjectBytes: SUBJECT_BYTES,
        reservationBytes: reservation.bytes,
        terminalBytes: terminal.bytes,
        archiveBytes: changed,
      }),
    'replay-nondeterministic'
  );
});
