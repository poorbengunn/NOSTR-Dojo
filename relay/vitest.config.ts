import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/__tests__/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json'],
      include: ['src/**/*.ts'],
      exclude: ['src/__tests__/**', 'src/cli.ts', 'src/index.ts'],
    },
    testTimeout: 10000,
    hookTimeout: 10000,
  },
});
