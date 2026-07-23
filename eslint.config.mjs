import { generateEslintConfig } from '@companion-module/tools/eslint/config.mjs';

const companionConfig = await generateEslintConfig({
  enableTypescript: true,
});

export default [
  ...companionConfig,
  {
    name: 'overlaykit/governance-host-compatibility',
    files: ['tools/governance/**/*.ts'],
    rules: {
      '@typescript-eslint/no-base-to-string': 'off',
      'n/hashbang': 'off',
      'n/no-unsupported-features/es-builtins': 'off',
      'n/no-unsupported-features/es-syntax': 'off',
      'n/no-unsupported-features/node-builtins': 'off',
    },
  },
];
