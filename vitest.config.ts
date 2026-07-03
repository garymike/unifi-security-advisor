import { defineConfig } from 'vitest/config';

// Dedicated Vitest config. Vitest prefers this over vite.config.ts, so the
// unit tests run WITHOUT booting the SvelteKit + Tailwind plugin pipeline.
// Every test under src/**/__tests__ and tests/** is framework-agnostic Node
// code (the audit core, DB schema, wizard logic) — none touch Svelte, the
// DOM, or Tailwind — so esbuild's native TS transform is all that's needed.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    // The desktop app's SvelteKit routes/components are not unit-tested here.
    exclude: ['**/node_modules/**', '**/dist/**', '**/build/**', 'src-tauri/**'],
  },
});
