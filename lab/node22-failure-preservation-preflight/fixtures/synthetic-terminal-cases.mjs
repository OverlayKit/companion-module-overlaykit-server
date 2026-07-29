export const BRANCHES = Object.freeze([
  'launch-failure',
  'malformed-output',
  'divergent-attempts',
  'exact-incompatibility',
  'success',
]);

export const EXPECTED_PROTOCOL = Object.freeze({
  compatibility: 'compatible',
  marker: 'node22-failure-preservation-v1',
});

const EXPECTED_BYTES = Buffer.from(`${JSON.stringify(EXPECTED_PROTOCOL)}\n`, 'utf8');
const DIVERGENT_BYTES = Buffer.from(
  `${JSON.stringify({
    compatibility: 'compatible',
    marker: 'node22-failure-preservation-v1-divergent',
  })}\n`,
  'utf8'
);
const INCOMPATIBLE_BYTES = Buffer.from(
  `${JSON.stringify({
    compatibility: 'incompatible',
    marker: 'node22-failure-preservation-v1',
  })}\n`,
  'utf8'
);
const MALFORMED_BYTES = Buffer.from('{"accepted":true', 'utf8');

function attempt(ordinal, stdout) {
  return {
    exitCode: 0,
    ordinal,
    signal: null,
    stderr: Buffer.alloc(0),
    stdout: Buffer.from(stdout),
  };
}

export function executeSyntheticCase(branchId) {
  if (!BRANCHES.includes(branchId)) {
    throw new TypeError(`unknown synthetic terminal case: ${String(branchId)}`);
  }

  if (branchId === 'launch-failure') {
    return {
      launchError: {
        code: 'SYNTHETIC_LAUNCH_FAILED',
        syscall: 'synthetic-launch',
      },
      attempts: [],
    };
  }

  if (branchId === 'malformed-output') {
    return {
      launchError: null,
      attempts: [attempt(1, MALFORMED_BYTES)],
    };
  }

  if (branchId === 'divergent-attempts') {
    return {
      launchError: null,
      attempts: [attempt(1, EXPECTED_BYTES), attempt(2, DIVERGENT_BYTES)],
    };
  }

  if (branchId === 'exact-incompatibility') {
    return {
      launchError: null,
      attempts: [attempt(1, INCOMPATIBLE_BYTES), attempt(2, INCOMPATIBLE_BYTES)],
    };
  }

  return {
    launchError: null,
    attempts: [attempt(1, EXPECTED_BYTES), attempt(2, EXPECTED_BYTES)],
  };
}
