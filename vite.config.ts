import { defineConfig } from 'vite';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  envPrefix: ['VITE_', 'TAURI_'],
  build: { target: 'chrome105' },
  optimizeDeps: { exclude: ['undici'] },
  ssr: { noExternal: ['@tauri-apps/plugin-http', '@tauri-apps/plugin-sql', '@tauri-apps/plugin-dialog'] },
});
