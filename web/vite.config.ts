import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // When embedded in Go, all API calls proxy to the Go server.
  // In dev, proxy to localhost:8443 (pane serve).
  server: {
    proxy: {
      '/api': 'https://localhost:8443',
      '/auth': 'https://localhost:8443',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
