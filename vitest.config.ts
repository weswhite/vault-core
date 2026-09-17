import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    // The package is developed on an external non-APFS volume, which sprays
    // AppleDouble `._*` resource-fork files next to every real file. They are
    // not TypeScript and vitest fails trying to parse them.
    exclude: ['**/node_modules/**', '**/dist/**', '**/._*'],
  },
});
