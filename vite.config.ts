import { defineConfig } from 'vite';
import { sveltekit } from '@sveltejs/kit/vite';
import adapter from '@sveltejs/adapter-static';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  // SvelteKit 3 no longer reads svelte.config.js; former kit.* options are
  // passed to the sveltekit() plugin. We prerender to a SPA fallback for Tauri.
  plugins: [tailwindcss(), sveltekit({ adapter: adapter({ fallback: 'index.html' }) })],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  envPrefix: ['VITE_', 'TAURI_'],
  build: { target: 'chrome105' },
  optimizeDeps: { exclude: ['undici'] },
  ssr: { noExternal: ['@tauri-apps/plugin-http', '@tauri-apps/plugin-sql', '@tauri-apps/plugin-dialog'] },
});
