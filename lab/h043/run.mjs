#!/usr/bin/env node

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  H042_EVIDENCE_SHA256,
  H042_REPLAY_ARCHIVE_PATH,
  H042_REPLAY_ARCHIVE_RELATIVE_PATH,
  H042_REPLAY_ARCHIVE_SHA256,
  H042_RUN_ID,
  H042_RUN_MEMBER_PATH,
  H042_VERIFICATION_MEMBER_PATH,
  readTarGzipMembers,
} from './archive-lib.mjs';
import {
  H043_CLAIM_BOUNDARY,
  H043_SIDE_EFFECT_AUDIT,
  classificationExactShape,
  classifyPrefix,
} from './eligibility-lib.mjs';
import {
  buildH042Prefix,
  parseJsonLines,
  prefixManifest,
  rebuildPrefixRaw,
  serializeJsonLines,
  sha256,
  sha256Canonical,
} from './prefix-lib.mjs';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const H042_MEMBER_ROOT = H042_RUN_MEMBER_PATH.slice(0, -'run.json'.length);
const H042_RUN_SHA256 = 'be39e69140f733e7f56e371f144b6e7b0cd43c05b7be6bfea9850c440679a7b6';
const H042_VERIFICATION_SHA256 = '0fc4f3cd7f78fe1184331a40f97874521d97d6f5c677a4829588a6dc676e6919';
const REPOSITORY = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git';

export const H043_REQUIRED_SOURCES = Object.freeze(
  [
    '.overlaykit/governance/changes/CHG-0014.json',
    '.overlaykit/governance/changes/CHG-0015.json',
    '.overlaykit/governance/decisions/ADR-0006.json',
    'lab/h043/adversarial-regression.test.mjs',
    'lab/h043/archive-lib.mjs',
    'lab/h043/archive-lib.test.mjs',
    'lab/h043/eligibility-lib.mjs',
    'lab/h043/eligibility-lib.test.mjs',
    'lab/h043/prefix-lib.mjs',
    'lab/h043/prefix-lib.test.mjs',
    'lab/h043/run.mjs',
    'lab/h043/run.test.mjs',
    'lab/h043/schema.test.mjs',
    'lab/h043/schemas/offline-worker-eligibility-run.schema.json',
    'lab/h043/verify.mjs',
    'lab/h043/verify.test.mjs',
    'package-lock.json',
    'package.json',
  ].sort()
);

const H043_BASE_COMMIT = 'dce2cd8bb454a264f8f9738f9748dc1c70b5dcd0';
const H043_CHANGE_SHA256 = 'b2cd667fad87b366163549cdb3b0ffaac95ffd591fc53d6158c229a516ae7e25';
const H043_PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const H043_MANIFEST_CONTENT_HASH =
  'b29bde1b9f24a5c0ddaaa6b18cb577de859d6d9577b6636148c4ebeb021b8917';

export const H043_REQUIRED_CASE_IDS = Object.freeze([
  'canonical-golden',
  'healthy-baseline',
  'device-absent',
  'negative-window-open',
  'current-descriptor-reacquired',
  'ordered-markers-changed',
  'partial-marker-change',
  'worker-missing',
  'multiple-workers',
  'container-lifecycle-drift',
  'pid1-identity-drift',
  'worker-pid-changed',
  'worker-startticks-changed',
  'worker-ppid-changed',
  'worker-parent-startticks-changed',
  'worker-pid-namespace-changed',
  'worker-full-tuple-drift',
  'exact-absence-missing',
  'usb-epoch-identity-mismatch',
  'returned-node-mismatch',
  'negative-window-boundary-missing',
  'late-positive',
  'prefix-tail-contamination',
  'duplicate-candidates',
  'unapproved-command',
]);

function clone(value) {
  return structuredClone(value);
}

function same(left, right) {
  return sha256Canonical(left) === sha256Canonical(right);
}

function memberBytes(members, name) {
  const value = members.get(`${H042_MEMBER_ROOT}${name}`);
  if (!value) throw new Error(`H-043 input is missing H-042 replay member ${name}`);
  return value;
}

function memberText(members, name) {
  return memberBytes(members, name).toString('utf8');
}

async function collectSources() {
  return Promise.all(
    H043_REQUIRED_SOURCES.map(async (relativePath) => ({
      path: relativePath,
      sha256: sha256(await readFile(path.join(REPOSITORY_ROOT, relativePath))),
    }))
  );
}

export async function loadCanonicalH042Archive() {
  const archiveBytes = await readFile(H042_REPLAY_ARCHIVE_PATH);
  if (sha256(archiveBytes) !== H042_REPLAY_ARCHIVE_SHA256) {
    throw new Error('H-043 H-042 replay archive hash mismatch');
  }
  const members = readTarGzipMembers(archiveBytes);
  const runBytes = memberBytes(members, 'run.json');
  const verificationBytes = memberBytes(members, 'verification.json');
  if (sha256(runBytes) !== H042_RUN_SHA256) {
    throw new Error('H-043 canonical H-042 run hash mismatch');
  }
  if (sha256(verificationBytes) !== H042_VERIFICATION_SHA256) {
    throw new Error('H-043 canonical H-042 verification hash mismatch');
  }
  const run = JSON.parse(runBytes.toString('utf8'));
  const verification = JSON.parse(verificationBytes.toString('utf8'));
  if (
    run.runId !== H042_RUN_ID ||
    run.evidenceSha256 !== H042_EVIDENCE_SHA256 ||
    verification.runId !== H042_RUN_ID ||
    verification.evidenceSha256 !== H042_EVIDENCE_SHA256 ||
    verification.verified !== true ||
    verification.outcome !== 'supported'
  ) {
    throw new Error('H-043 H-042 accepted lineage receipt mismatch');
  }
  return {
    archiveBytes,
    members,
    run,
    verification,
    runtimePollText: memberText(members, 'runtime-poll.jsonl'),
    hostPollText: memberText(members, 'host-poll.jsonl'),
    logsInitialText: memberText(members, 'logs-initial.txt'),
    logsAbsentText: memberText(members, 'logs-absent.txt'),
    logsPreSignalText: memberText(members, 'logs-pre-signal.txt'),
  };
}

function currentNodeDescriptor(prefix) {
  const stat = prefix.context.observations.preSignal.host.hidraw.find(
    (entry) => entry.serialMatches
  ).stat;
  return {
    descriptor: '20',
    target: '/host-dev/hidraw0',
    stat: clone(stat),
    fdinfoSha256: 'a'.repeat(64),
  };
}

function synchronizePreSignalSummary(prefix) {
  const observation = prefix.context.observations.preSignal;
  const initialMarkers = prefix.context.observations.initial.runtime.markers;
  const finalMarkers = observation.runtime.markers;
  const currentStat = observation.host.hidraw.find((entry) => entry.serialMatches)?.stat;
  const descriptorObserved = observation.runtime.observer.surfaceWorkers.some((worker) =>
    worker.fileDescriptors.some(
      (descriptor) =>
        descriptor.stat?.inode === currentStat?.inode &&
        descriptor.stat?.rdev === currentStat?.rdev &&
        descriptor.stat?.major === currentStat?.major &&
        descriptor.stat?.minor === currentStat?.minor &&
        descriptor.stat?.isCharacterDevice === true
    )
  );
  const openingObserved = finalMarkers.opening > initialMarkers.opening;
  const readyObserved = finalMarkers.ready > initialMarkers.ready;
  observation.markers = {
    baseline: clone(initialMarkers),
    final: clone(finalMarkers),
  };
  observation.control = {
    descriptorObserved,
    openingObserved,
    readyObserved,
    boundaryNegative:
      prefix.context.windows.preSignal.deadlineExpired === true &&
      !descriptorObserved &&
      !openingObserved &&
      !readyObserved,
  };
}

function mutateFinalRuntime(prefix, mutateWorker, mutateRuntime) {
  const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'H-043 hostile runtime');
  const final = entries.at(-1);
  mutateWorker?.(final.observer.surfaceWorkers, final);
  mutateRuntime?.(final);
  const candidate = rebuildPrefixRaw(prefix, { runtimeEntries: entries });
  candidate.context.observations.preSignal.runtime = clone(final);
  synchronizePreSignalSummary(candidate);
  return candidate;
}

function mutateFinalHost(prefix, mutateHost) {
  const entries = parseJsonLines(prefix.raw.hostPoll.text, 'H-043 hostile host');
  const final = entries.at(-1);
  mutateHost(final);
  const candidate = rebuildPrefixRaw(prefix, { hostEntries: entries });
  candidate.context.observations.preSignal.host = clone(final);
  synchronizePreSignalSummary(candidate);
  return candidate;
}

function openNegativeWindow(prefix) {
  const candidate = clone(prefix);
  const started = BigInt(candidate.context.windows.preSignal.startedMonotonicNs);
  const runtime = parseJsonLines(candidate.raw.runtimePoll.text, 'H-043 open-window runtime');
  const finalRuntime = runtime.find((entry) => BigInt(entry.monotonicNs) >= started);
  if (!finalRuntime) throw new Error('H-043 hostile open window has no post-return runtime');
  const cutoff = BigInt(finalRuntime.monotonicNs) + 1n;
  const runtimeEntries = runtime.filter(
    (entry) => BigInt(entry.monotonicNs) <= BigInt(finalRuntime.monotonicNs)
  );
  const hostEntries = parseJsonLines(candidate.raw.hostPoll.text, 'H-043 open-window host').filter(
    (entry) => BigInt(entry.monotonicNs) < cutoff
  );
  const finalHost = clone(candidate.context.observations.returned.host);
  finalHost.capturedAt = finalRuntime.capturedAt;
  finalHost.monotonicNs = cutoff.toString();
  hostEntries.push(finalHost);
  const auditEntries = candidate.context.invocationAuditPrefix.filter(
    (entry) => BigInt(entry.monotonicNs) <= cutoff
  );

  let rebuilt = rebuildPrefixRaw(candidate, {
    runtimeEntries,
    hostEntries,
    auditEntries,
  });
  rebuilt.cutoffMonotonicNs = cutoff.toString();
  rebuilt.context.observations.preSignal.host = clone(finalHost);
  rebuilt.context.observations.preSignal.runtime = clone(finalRuntime);
  rebuilt.context.companion.preSignalLifecycle = clone(finalRuntime.lifecycle);
  rebuilt.context.companion.workerLifecycle.preSignal = clone(finalRuntime.observer.surfaceWorkers);
  rebuilt.context.windows.preSignal.completedAt = finalHost.capturedAt;
  rebuilt.context.windows.preSignal.completedMonotonicNs = cutoff.toString();
  rebuilt.context.windows.preSignal.deadlineExpired = false;
  rebuilt.context.windows.preSignal.boundaryNegative = false;
  synchronizePreSignalSummary(rebuilt);
  return rebuilt;
}

function hostileDefinitions(prefix) {
  return [
    {
      id: 'canonical-golden',
      expectedDisposition: 'candidate',
      expectedCandidateCount: 1,
      mutate: (value) => value,
    },
    {
      id: 'healthy-baseline',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers, runtime) => {
          workers[0].fileDescriptors = [currentNodeDescriptor(value)];
          runtime.markers.opening += 1;
          runtime.markers.ready += 1;
        });
      },
    },
    {
      id: 'device-absent',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        const absent = value.context.observations.absent.host;
        return mutateFinalHost(value, (host) => {
          for (const key of ['lsusb', 'usb', 'hidraw', 'priorPath', 'errors', 'state']) {
            host[key] = clone(absent[key]);
          }
        });
      },
    },
    {
      id: 'negative-window-open',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate: openNegativeWindow,
    },
    {
      id: 'current-descriptor-reacquired',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].fileDescriptors = [currentNodeDescriptor(value)];
        });
      },
    },
    {
      id: 'ordered-markers-changed',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, null, (runtime) => {
          runtime.markers.opening += 1;
          runtime.markers.ready += 1;
        });
      },
    },
    {
      id: 'partial-marker-change',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, null, (runtime) => {
          runtime.markers.opening += 1;
        });
      },
    },
    {
      id: 'worker-missing',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => workers.splice(0));
      },
    },
    {
      id: 'multiple-workers',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers.push({ ...clone(workers[0]), pid: 999, startTicks: 999 });
        });
      },
    },
    {
      id: 'container-lifecycle-drift',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const candidate = mutateFinalRuntime(value, null, (runtime) => {
          runtime.lifecycle.restartCount = 1;
        });
        candidate.context.companion.preSignalLifecycle.restartCount = 1;
        return candidate;
      },
    },
    {
      id: 'pid1-identity-drift',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const candidate = mutateFinalRuntime(value, null, (runtime) => {
          runtime.lifecycle.pid1StartTicks += 1;
        });
        candidate.context.companion.preSignalLifecycle.pid1StartTicks += 1;
        return candidate;
      },
    },
    {
      id: 'worker-pid-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].pid += 1;
        });
      },
    },
    {
      id: 'worker-startticks-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].startTicks += 1;
        });
      },
    },
    {
      id: 'worker-ppid-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].ppid += 1;
        });
      },
    },
    {
      id: 'worker-parent-startticks-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].parentStartTicks += 1;
        });
      },
    },
    {
      id: 'worker-pid-namespace-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].pidNamespace = 'pid:[999]';
        });
      },
    },
    {
      id: 'worker-full-tuple-drift',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateFinalRuntime(value, (workers) => {
          workers[0].mountNamespace = 'mnt:[999]';
        });
      },
    },
    {
      id: 'exact-absence-missing',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.context.observations.absent.host.state = 'present';
        value.context.observations.absent.host.usb = clone(
          value.context.observations.initial.host.usb
        );
        return value;
      },
    },
    {
      id: 'usb-epoch-identity-mismatch',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.context.observations.returned.host.usb[0].deviceNumber =
          value.context.observations.initial.host.usb[0].deviceNumber;
        return value;
      },
    },
    {
      id: 'returned-node-mismatch',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.context.observations.preSignal.host.hidraw[0].stat.inode = '9999';
        return value;
      },
    },
    {
      id: 'negative-window-boundary-missing',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const deadline =
          BigInt(value.context.windows.preSignal.startedMonotonicNs) + 30_000_000_000n;
        const entries = parseJsonLines(value.raw.runtimePoll.text, 'H-043 hostile runtime').filter(
          (entry) =>
            entry.phase === 'signal-target-revalidate' || BigInt(entry.monotonicNs) < deadline
        );
        return rebuildPrefixRaw(value, { runtimeEntries: entries });
      },
    },
    {
      id: 'late-positive',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const deadline =
          BigInt(value.context.windows.preSignal.startedMonotonicNs) + 30_000_000_000n;
        const entries = parseJsonLines(value.raw.runtimePoll.text, 'H-043 hostile runtime');
        const boundary = entries.find((entry) => BigInt(entry.monotonicNs) >= deadline);
        boundary.markers.opening += 1;
        return rebuildPrefixRaw(value, { runtimeEntries: entries });
      },
    },
    {
      id: 'prefix-tail-contamination',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.futureSignal = { signal: 'SIGTERM' };
        return value;
      },
    },
    {
      id: 'duplicate-candidates',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      duplicateOutput: true,
      mutate: (value) => value,
    },
    {
      id: 'unapproved-command',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const audit = clone(value.context.invocationAuditPrefix);
        const last = audit.at(-1);
        audit.push({
          at: last.at,
          monotonicNs: (BigInt(last.monotonicNs) + 1n).toString(),
          kind: 'docker-exec-signal',
          phase: 'fault-injection',
        });
        return rebuildPrefixRaw(value, { auditEntries: audit });
      },
    },
  ];
}

export function evaluateHostileMatrix(prefix, { tailIndependent }) {
  const cases = hostileDefinitions(prefix).map((definition) => {
    const input = definition.mutate(clone(prefix));
    let classification = classifyPrefix(input);
    if (definition.duplicateOutput) {
      const canonical = classifyPrefix(input);
      const duplicated = {
        ...canonical,
        candidates: [canonical.candidates[0], clone(canonical.candidates[0])],
      };
      if (!classificationExactShape(duplicated)) {
        classification = {
          disposition: 'inconclusive',
          stage: 'source-admission',
          reasonCode: 'duplicate-candidate-output',
          predicates: clone(canonical.predicates),
          candidates: [],
        };
      }
    }
    const actualCandidateCount = classification.candidates.length;
    const passed =
      classification.disposition === definition.expectedDisposition &&
      actualCandidateCount === definition.expectedCandidateCount;
    return {
      id: definition.id,
      inputSha256: sha256Canonical(input),
      expectedDisposition: definition.expectedDisposition,
      actualDisposition: classification.disposition,
      expectedCandidateCount: definition.expectedCandidateCount,
      actualCandidateCount,
      stage: classification.stage,
      reasonCode: classification.reasonCode,
      passed,
    };
  });
  const passedCount = cases.filter((entry) => entry.passed).length;
  return {
    schemaVersion: 'overlaykit-h043-hostile-matrix/v1',
    requiredCaseIds: [...H043_REQUIRED_CASE_IDS],
    caseCount: cases.length,
    passedCount,
    allPassed: passedCount === cases.length,
    tailIndependent,
    cases,
  };
}

export function evaluateTailIndependence(input, canonicalPrefix) {
  const mutatedRun = clone(input.run);
  mutatedRun.windows.signal = { arbitrary: 'changed' };
  mutatedRun.windows.postSignal = { arbitrary: 'changed' };
  mutatedRun.observations.postSignal = { arbitrary: 'changed' };
  mutatedRun.predicates = { arbitrary: false };
  mutatedRun.outcome = { status: 'refuted' };
  mutatedRun.cleanup = { arbitrary: true };
  mutatedRun.completedAt = '2099-01-01T00:00:00.000Z';
  mutatedRun.invocationAudit.entries = mutatedRun.invocationAudit.entries.map((entry) =>
    BigInt(entry.monotonicNs) > BigInt(canonicalPrefix.cutoffMonotonicNs)
      ? { ...entry, kind: 'arbitrary-future-tail', phase: 'arbitrary-future-tail' }
      : entry
  );

  const runtimeEntries = parseJsonLines(input.runtimePollText, 'H-042 runtime poll').map((entry) =>
    BigInt(entry.monotonicNs) > BigInt(canonicalPrefix.cutoffMonotonicNs)
      ? { ...entry, phase: 'arbitrary-future-tail' }
      : entry
  );
  const hostEntries = parseJsonLines(input.hostPollText, 'H-042 host poll').map((entry) =>
    BigInt(entry.monotonicNs) > BigInt(canonicalPrefix.cutoffMonotonicNs)
      ? { ...entry, state: 'arbitrary-future-tail' }
      : entry
  );
  const mutatedPrefix = buildH042Prefix({
    run: mutatedRun,
    runtimePollText: serializeJsonLines(runtimeEntries),
    hostPollText: serializeJsonLines(hostEntries),
    logsInitialText: input.logsInitialText,
    logsAbsentText: input.logsAbsentText,
    logsPreSignalText: input.logsPreSignalText,
  });
  return (
    same(mutatedPrefix, canonicalPrefix) &&
    same(classifyPrefix(mutatedPrefix), classifyPrefix(canonicalPrefix))
  );
}

function runIdFor(startedAt, prefixSha256) {
  const timestamp = startedAt.replace(/[:.]/gu, '-');
  return `h043-${timestamp}-${sha256(`${startedAt}:${prefixSha256}`).slice(0, 8)}`;
}

function validUtcTimestamp(value) {
  if (typeof value !== 'string') return false;
  const match =
    /^(?<year>[0-9]{4})-(?<month>0[1-9]|1[0-2])-(?<day>0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u.exec(
      value
    );
  if (!match) return false;
  const year = Number(match.groups.year);
  const month = Number(match.groups.month);
  const day = Number(match.groups.day);
  const leapYear = year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= daysInMonth[month - 1] && Number.isFinite(Date.parse(value));
}

function causalBoundaryFor(input, prefix) {
  const faultEntries = input.run.invocationAudit.entries
    .map((entry, sourceAuditIndex) => ({ entry, sourceAuditIndex }))
    .filter(
      ({ entry }) => entry.kind === 'docker-exec-signal' || entry.phase === 'fault-injection'
    );
  if (faultEntries.length === 0) {
    throw new Error('H-043 source has no post-cutoff fault-injection boundary');
  }
  const first = faultEntries[0];
  const cutoff = BigInt(prefix.cutoffMonotonicNs);
  const fault = BigInt(first.entry.monotonicNs);
  if (
    first.sourceAuditIndex !== 223 ||
    first.entry.kind !== 'docker-exec-signal' ||
    first.entry.phase !== 'fault-injection' ||
    cutoff >= fault
  ) {
    throw new Error('H-043 first fault-injection identity or chronology mismatch');
  }
  return {
    cutoffMonotonicNs: prefix.cutoffMonotonicNs,
    firstFaultInjection: {
      sourceAuditIndex: first.sourceAuditIndex,
      at: first.entry.at,
      monotonicNs: first.entry.monotonicNs,
      kind: first.entry.kind,
      phase: first.entry.phase,
      entrySha256: sha256Canonical(first.entry),
    },
    gapNs: (fault - cutoff).toString(),
    precedesFirstFaultInjection: true,
  };
}

export function outcomeFor(classification, matrix, sideEffectAudit, sourceStable) {
  if (!sideEffectAudit.passed) {
    return {
      status: 'refuted',
      stage: 'side-effect-boundary',
      reasonCode: 'side-effect-observed',
    };
  }
  if (!matrix.allPassed || !matrix.tailIndependent) {
    return {
      status: 'refuted',
      stage: 'hostile-matrix',
      reasonCode: 'hostile-case-or-tail-independence-failed',
    };
  }
  if (!sourceStable) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'source-set-unstable',
    };
  }
  if (classification.disposition === 'withheld') {
    return {
      status: 'refuted',
      stage: 'canonical-classification',
      reasonCode: 'canonical-prefix-not-eligible',
    };
  }
  if (classification.disposition === 'inconclusive') {
    return {
      status: 'inconclusive',
      stage: 'prefix-boundary',
      reasonCode: 'canonical-prefix-inconclusive',
    };
  }
  if (classification.disposition === 'candidate' && classification.candidates.length === 1) {
    return {
      status: 'supported',
      stage: 'offline-worker-eligibility',
      reasonCode: 'canonical-candidate-and-hostile-matrix-exact',
    };
  }
  return {
    status: 'inconclusive',
    stage: 'prefix-boundary',
    reasonCode: 'canonical-prefix-inconclusive',
  };
}

export async function buildRun({ startedAt = new Date().toISOString() } = {}) {
  if (!validUtcTimestamp(startedAt)) {
    throw new Error(`H-043 startedAt is not a valid UTC timestamp: ${startedAt}`);
  }
  const sourceBefore = await collectSources();
  const [input, manifestBytes, planBytes, changeBytes] = await Promise.all([
    loadCanonicalH042Archive(),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/plan.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0015.json')),
  ]);
  if (process.version !== 'v22.20.0') {
    throw new Error(`H-043 requires Node v22.20.0, observed ${process.version}`);
  }

  const prefix = buildH042Prefix(input);
  const prefixReceipt = prefixManifest(prefix);
  const causalBoundary = causalBoundaryFor(input, prefix);
  const canonicalClassification = classifyPrefix(prefix);
  const tailIndependent = evaluateTailIndependence(input, prefix);
  const hostileMatrix = evaluateHostileMatrix(prefix, { tailIndependent });
  const sideEffectAudit = clone(H043_SIDE_EFFECT_AUDIT);
  const sourceAfter = await collectSources();
  const sourceStable = same(sourceBefore, sourceAfter);
  const completedAt = new Date().toISOString();
  if (!validUtcTimestamp(completedAt) || Date.parse(completedAt) < Date.parse(startedAt)) {
    throw new Error('H-043 completion timestamp precedes its start');
  }
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const plan = JSON.parse(planBytes.toString('utf8'));
  if (
    sha256(changeBytes) !== H043_CHANGE_SHA256 ||
    plan.planHash !== H043_PLAN_HASH ||
    manifest.contentHash !== H043_MANIFEST_CONTENT_HASH
  ) {
    throw new Error('H-043 historical governance baseline mismatch');
  }

  const record = {
    schemaVersion: 'overlaykit-h043-offline-worker-eligibility-run/v1',
    hypothesis: 'H-043',
    runId: runIdFor(startedAt, prefixReceipt.prefixSha256),
    startedAt,
    completedAt,
    outcome: outcomeFor(canonicalClassification, hostileMatrix, sideEffectAudit, sourceStable),
    collector: {
      node: process.version,
      repository: REPOSITORY,
      baseCommit: H043_BASE_COMMIT,
      sources: sourceBefore,
      sourceStable,
      governance: {
        changeId: 'CHG-0015',
        changeSha256: sha256(changeBytes),
        planHash: plan.planHash,
        manifestContentHash: manifest.contentHash,
      },
    },
    input: {
      archivePath: H042_REPLAY_ARCHIVE_RELATIVE_PATH,
      archiveSha256: H042_REPLAY_ARCHIVE_SHA256,
      h042RunId: H042_RUN_ID,
      h042EvidenceSha256: H042_EVIDENCE_SHA256,
      h042RunSha256: H042_RUN_SHA256,
      h042VerificationSha256: H042_VERIFICATION_SHA256,
    },
    prefix: prefixReceipt,
    causalBoundary,
    canonicalClassification,
    hostileMatrix,
    sideEffectAudit,
    claimBoundary: clone(H043_CLAIM_BOUNDARY),
  };
  return { ...record, evidenceSha256: sha256Canonical(record) };
}

export async function writeRun(options = {}) {
  const run = await buildRun(options);
  const outputRoot = options.outputRoot ?? path.join(REPOSITORY_ROOT, 'artifacts', 'h043');
  const runDirectory = path.join(outputRoot, run.runId);
  await mkdir(runDirectory, { recursive: true });
  const runPath = path.join(runDirectory, 'run.json');
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`, { flag: 'wx' });
  return { run, runPath };
}

function isDirectInvocation() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectInvocation()) {
  try {
    const { run, runPath } = await writeRun();
    process.stdout.write(
      `${JSON.stringify({
        runId: run.runId,
        outcome: run.outcome,
        evidenceSha256: run.evidenceSha256,
        runPath: path.relative(REPOSITORY_ROOT, runPath),
      })}\n`
    );
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
