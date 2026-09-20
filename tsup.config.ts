import { defineConfig } from 'tsup';

// Dual CJS + ESM. The backend is commonjs, the web build is ESM through Vite,
// and Metro resolves `main`. All three have to work from one publish.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    crypto: 'src/crypto.ts',
    read: 'src/read.ts',
    migration: 'src/migration.ts',
    testvectors: 'src/testvectors.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  splitting: false,
  treeshake: true,
});
