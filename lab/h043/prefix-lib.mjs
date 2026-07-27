import { createHash } from 'node:crypto';

export const H043_PREFIX_SCHEMA = 'overlaykit-h043-h042-prefix/v1';
export const H043_ARCHIVE_SHA256 =
  '15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36';
export const H043_H042_RUN_ID = 'h042-2026-07-26T16-19-05-858Z-efaf85fa';
export const H043_H042_EVIDENCE_SHA256 =
  'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88';
export const H043_H042_RUN_SHA256 =
  'be39e69140f733e7f56e371f144b6e7b0cd43c05b7be6bfea9850c440679a7b6';
export const H043_H042_VERIFICATION_SHA256 =
  '0fc4f3cd7f78fe1184331a40f97874521d97d6f5c677a4829588a6dc676e6919';
export const H043_CANONICAL_PREFIX_SHA256 =
  'aee82f2da74cee96a7ac10ea21946d1e668913e1bb2e2210398b4a362eff3959';

export const H043_CANONICAL_PREFIX_RECEIPTS = Object.freeze({
  runtimePoll: Object.freeze({
    lineCount: 55,
    sha256: 'ec7f7041a505524d2ba058b3185373633135cab0765f46a2d4ddab9f260d725f',
  }),
  hostPoll: Object.freeze({
    lineCount: 476,
    sha256: '53b91505477301d9a1a554f6a15dc41b138158df702339daa48139b810a3a4b4',
  }),
  invocationAudit: Object.freeze({
    entryCount: 223,
    sha256: 'bfc457e62f58cc581b3ad653cc9b45ee397ef6fc8a2be0d96f3cb003e0d7a8ef',
  }),
  logsInitial: '27534063c7d53c75a8b20f8b0a50c4b0ca01bd09763baab7716fc062e50263e6',
  logsAbsent: '0b62162131e526aa07efc175a626623e885e9965362f833936d2e494391a4abb',
  logsPreSignal: 'f5375408668603381d24b9289b307636b86db462022fd5fedfd1726fbc9e5d8b',
  cutoffMonotonicNs: '78174124595205',
});

const PREFIX_KEYS = Object.freeze([
  'schemaVersion',
  'source',
  'cutoffMonotonicNs',
  'context',
  'raw',
]);

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

export function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

export function parseJsonLines(text, label) {
  if (typeof text !== 'string' || !text.endsWith('\n')) {
    throw new TypeError(`${label} must be newline-terminated JSONL`);
  }
  const lines = text.slice(0, -1).split('\n');
  if (lines.some((line) => line === '')) {
    throw new TypeError(`${label} contains an empty JSONL record`);
  }
  return lines.map((line, index) => {
    try {
      const value = JSON.parse(line);
      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError('record is not an object');
      }
      return value;
    } catch (error) {
      throw new TypeError(`${label} line ${index + 1} is invalid: ${error.message}`);
    }
  });
}

export function serializeJsonLines(entries) {
  return `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
}

function monotonic(value, label) {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) {
    throw new TypeError(`${label} is not an unsigned monotonic nanosecond value`);
  }
  return BigInt(value);
}

function prefixJsonLines(text, cutoff, label) {
  const entries = parseJsonLines(text, label);
  const prefix = entries.filter(
    (entry) => monotonic(entry.monotonicNs, `${label}.monotonicNs`) <= cutoff
  );
  return {
    text: serializeJsonLines(prefix),
    entries: prefix,
  };
}

function clone(value) {
  return structuredClone(value);
}

function sourceDescriptor() {
  return {
    archiveSha256: H043_ARCHIVE_SHA256,
    h042RunId: H043_H042_RUN_ID,
    h042EvidenceSha256: H043_H042_EVIDENCE_SHA256,
    h042RunSha256: H043_H042_RUN_SHA256,
    h042VerificationSha256: H043_H042_VERIFICATION_SHA256,
  };
}

function selectedCompanion(companion) {
  return {
    name: companion?.name,
    containerId: companion?.containerId,
    imageReference: companion?.imageReference,
    imageId: companion?.imageId,
    repoDigests: clone(companion?.repoDigests),
    version: companion?.version,
    revision: companion?.revision,
    dynamicRoot: companion?.dynamicRoot,
    dynamicPath: companion?.dynamicPath,
    compatibilityPath: companion?.compatibilityPath,
    deviceCgroupRule: companion?.deviceCgroupRule,
    deviceGid: companion?.deviceGid,
    staticDevices: clone(companion?.staticDevices),
    initialLifecycle: clone(companion?.initialLifecycle),
    absentLifecycle: clone(companion?.absentLifecycle),
    preSignalLifecycle: clone(companion?.preSignalLifecycle),
    workerLifecycle: {
      initial: clone(companion?.workerLifecycle?.initial),
      absent: clone(companion?.workerLifecycle?.absent),
      preSignal: clone(companion?.workerLifecycle?.preSignal),
    },
  };
}

export function buildH042Prefix({
  run,
  runtimePollText,
  hostPollText,
  logsInitialText,
  logsAbsentText,
  logsPreSignalText,
}) {
  if (run === null || typeof run !== 'object' || Array.isArray(run)) {
    throw new TypeError('H-042 run must be an object');
  }
  const cutoffMonotonicNs = run.observations?.preSignal?.host?.monotonicNs;
  const cutoff = monotonic(cutoffMonotonicNs, 'H-042 pre-signal host cutoff');
  const runtime = prefixJsonLines(runtimePollText, cutoff, 'runtime-poll.jsonl');
  const host = prefixJsonLines(hostPollText, cutoff, 'host-poll.jsonl');
  const invocationAuditPrefix = clone(
    run.invocationAudit?.entries?.filter(
      (entry) => monotonic(entry.monotonicNs, 'invocation audit monotonicNs') <= cutoff
    )
  );

  const prefix = {
    schemaVersion: H043_PREFIX_SCHEMA,
    source: sourceDescriptor(),
    cutoffMonotonicNs,
    context: {
      schemaVersion: run.schemaVersion,
      runId: run.runId,
      hypothesis: run.hypothesis,
      startedAt: run.startedAt,
      collector: clone(run.collector),
      host: clone(run.host),
      inputs: clone(run.inputs),
      device: clone(run.device),
      companion: selectedCompanion(run.companion),
      windows: {
        disconnect: clone(run.windows?.disconnect),
        reconnect: clone(run.windows?.reconnect),
        preSignal: clone(run.windows?.preSignal),
      },
      observations: {
        preflight: clone(run.observations?.preflight),
        initial: clone(run.observations?.initial),
        absent: clone(run.observations?.absent),
        returned: clone(run.observations?.returned),
        preSignal: clone(run.observations?.preSignal),
      },
      invocationAuditPrefix,
    },
    raw: {
      runtimePoll: {
        lineCount: runtime.entries.length,
        sha256: sha256(runtime.text),
        text: runtime.text,
      },
      hostPoll: {
        lineCount: host.entries.length,
        sha256: sha256(host.text),
        text: host.text,
      },
      invocationAudit: {
        entryCount: invocationAuditPrefix.length,
        sha256: sha256(`${canonicalJson(invocationAuditPrefix)}\n`),
      },
      logs: {
        initial: { sha256: sha256(logsInitialText), text: logsInitialText },
        absent: { sha256: sha256(logsAbsentText), text: logsAbsentText },
        preSignal: { sha256: sha256(logsPreSignalText), text: logsPreSignalText },
      },
    },
  };

  return prefix;
}

export function prefixShapeExact(prefix) {
  return (
    exactKeys(prefix, PREFIX_KEYS) &&
    prefix.schemaVersion === H043_PREFIX_SCHEMA &&
    exactKeys(prefix.source, [
      'archiveSha256',
      'h042RunId',
      'h042EvidenceSha256',
      'h042RunSha256',
      'h042VerificationSha256',
    ]) &&
    exactKeys(prefix.context, [
      'schemaVersion',
      'runId',
      'hypothesis',
      'startedAt',
      'collector',
      'host',
      'inputs',
      'device',
      'companion',
      'windows',
      'observations',
      'invocationAuditPrefix',
    ]) &&
    exactKeys(prefix.raw, ['runtimePoll', 'hostPoll', 'invocationAudit', 'logs'])
  );
}

export function prefixManifest(prefix) {
  return {
    schemaVersion: H043_PREFIX_SCHEMA,
    prefixSha256: sha256Canonical(prefix),
    cutoffMonotonicNs: prefix.cutoffMonotonicNs,
    runtimePoll: {
      lineCount: prefix.raw.runtimePoll.lineCount,
      sha256: prefix.raw.runtimePoll.sha256,
    },
    hostPoll: {
      lineCount: prefix.raw.hostPoll.lineCount,
      sha256: prefix.raw.hostPoll.sha256,
    },
    invocationAudit: clone(prefix.raw.invocationAudit),
    logs: {
      initialSha256: prefix.raw.logs.initial.sha256,
      absentSha256: prefix.raw.logs.absent.sha256,
      preSignalSha256: prefix.raw.logs.preSignal.sha256,
    },
  };
}

export function canonicalPrefixReceiptsExact(prefix) {
  const expected = H043_CANONICAL_PREFIX_RECEIPTS;
  return (
    prefix.raw.runtimePoll.lineCount === expected.runtimePoll.lineCount &&
    prefix.raw.runtimePoll.sha256 === expected.runtimePoll.sha256 &&
    sha256(prefix.raw.runtimePoll.text) === expected.runtimePoll.sha256 &&
    prefix.raw.hostPoll.lineCount === expected.hostPoll.lineCount &&
    prefix.raw.hostPoll.sha256 === expected.hostPoll.sha256 &&
    sha256(prefix.raw.hostPoll.text) === expected.hostPoll.sha256 &&
    prefix.raw.invocationAudit.entryCount === expected.invocationAudit.entryCount &&
    prefix.raw.invocationAudit.sha256 === expected.invocationAudit.sha256 &&
    sha256(`${canonicalJson(prefix.context.invocationAuditPrefix)}\n`) ===
      expected.invocationAudit.sha256 &&
    prefix.raw.logs.initial.sha256 === expected.logsInitial &&
    sha256(prefix.raw.logs.initial.text) === expected.logsInitial &&
    prefix.raw.logs.absent.sha256 === expected.logsAbsent &&
    sha256(prefix.raw.logs.absent.text) === expected.logsAbsent &&
    prefix.raw.logs.preSignal.sha256 === expected.logsPreSignal &&
    sha256(prefix.raw.logs.preSignal.text) === expected.logsPreSignal &&
    prefix.cutoffMonotonicNs === expected.cutoffMonotonicNs &&
    sha256Canonical(prefix) === H043_CANONICAL_PREFIX_SHA256
  );
}

export function sourceDescriptorExact(prefix) {
  return (
    prefix.source.archiveSha256 === H043_ARCHIVE_SHA256 &&
    prefix.source.h042RunId === H043_H042_RUN_ID &&
    prefix.source.h042EvidenceSha256 === H043_H042_EVIDENCE_SHA256 &&
    prefix.source.h042RunSha256 === H043_H042_RUN_SHA256 &&
    prefix.source.h042VerificationSha256 === H043_H042_VERIFICATION_SHA256 &&
    prefix.context.runId === H043_H042_RUN_ID &&
    prefix.context.hypothesis === 'H-042' &&
    prefix.context.schemaVersion === 'overlaykit-h042-surface-worker-recycle-run/v1'
  );
}

export function rebuildPrefixRaw(prefix, { runtimeEntries, hostEntries, auditEntries } = {}) {
  const candidate = clone(prefix);
  if (runtimeEntries) {
    const text = serializeJsonLines(runtimeEntries);
    candidate.raw.runtimePoll = {
      lineCount: runtimeEntries.length,
      sha256: sha256(text),
      text,
    };
  }
  if (hostEntries) {
    const text = serializeJsonLines(hostEntries);
    candidate.raw.hostPoll = {
      lineCount: hostEntries.length,
      sha256: sha256(text),
      text,
    };
  }
  if (auditEntries) {
    candidate.context.invocationAuditPrefix = clone(auditEntries);
    candidate.raw.invocationAudit = {
      entryCount: auditEntries.length,
      sha256: sha256(`${canonicalJson(auditEntries)}\n`),
    };
  }
  return candidate;
}
