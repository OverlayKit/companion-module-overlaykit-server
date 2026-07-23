import { rm } from 'node:fs/promises';

await Promise.all([
  rm(new URL('../dist', import.meta.url), { recursive: true, force: true }),
  rm(new URL('../pkg', import.meta.url), { recursive: true, force: true }),
  rm(new URL('../overlaykit-server-0.1.0.tgz', import.meta.url), { force: true }),
]);
