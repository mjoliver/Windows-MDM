// Standalone vitest config (no Vite plugins) so the test runner is decoupled
// from vite.config.ts. The project uses rolldown-based vite 8 whose plugin types
// are incompatible with the rollup-based vite that vitest bundles; keeping the
// test config plugin-free avoids that conflict at both typecheck and runtime.
// The unit tests here are plain TS (no JSX), so no react plugin is needed.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
