import { statfs } from 'node:fs/promises';

const GIBIBYTE = 1024n ** 3n;
export const CANONICAL_MINIMUM_FREE_GIB = 50;
export const SUPPLEMENTAL_MINIMUM_FREE_GIB = 16;

export function minimumFreeGiB(canonical, configuredValue) {
  const fallback = canonical ? CANONICAL_MINIMUM_FREE_GIB : SUPPLEMENTAL_MINIMUM_FREE_GIB;
  const value = configuredValue === undefined ? fallback : Number(configuredValue);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error('H034_MIN_FREE_GIB must be a positive number');
  }
  if (canonical && value < CANONICAL_MINIMUM_FREE_GIB) {
    throw new Error(`Canonical H-034 runs require at least ${CANONICAL_MINIMUM_FREE_GIB} GiB free`);
  }
  return value;
}

export async function storagePreflight(directory, requiredGiB) {
  const filesystem = await statfs(directory, { bigint: true });
  const availableBytes = filesystem.bavail * filesystem.bsize;
  const availableGiB = Number((availableBytes * 1000n) / GIBIBYTE) / 1000;
  return {
    availableBytes: availableBytes.toString(),
    availableGiB,
    requiredGiB,
    sufficient: availableGiB >= requiredGiB,
  };
}

export function assertStoragePreflight(result) {
  if (result.sufficient) return;
  throw new Error(
    `H-034 requires ${result.requiredGiB} GiB free before building; ` +
      `${result.availableGiB} GiB is available`
  );
}
