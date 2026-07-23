import { copyFile, mkdir } from 'node:fs/promises';

await mkdir(new URL('../pkg', import.meta.url), { recursive: true });
await Promise.all(
  ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'].map((file) =>
    copyFile(
      new URL(`../${file}`, import.meta.url),
      new URL(`../companion/${file}`, import.meta.url)
    )
  )
);
