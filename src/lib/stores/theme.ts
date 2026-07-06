import { writable } from 'svelte/store';

export type ThemeMode = 'system' | 'light' | 'dark';

const KEY = 'theme';

function storedMode(): ThemeMode {
  if (typeof localStorage === 'undefined') return 'system';
  const v = localStorage.getItem(KEY);
  return v === 'light' || v === 'dark' || v === 'system' ? v : 'system';
}

function prefersDark(): boolean {
  return typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches;
}

function resolve(mode: ThemeMode): 'light' | 'dark' {
  if (mode === 'system') return prefersDark() ? 'dark' : 'light';
  return mode;
}

function apply(mode: ThemeMode): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', resolve(mode));
}

let current: ThemeMode = storedMode();
export const themeMode = writable<ThemeMode>(current);

themeMode.subscribe((mode) => {
  current = mode;
  apply(mode);
  if (typeof localStorage !== 'undefined') {
    try { localStorage.setItem(KEY, mode); } catch { /* ignore */ }
  }
});

// While in system mode, follow live OS changes.
if (typeof matchMedia !== 'undefined') {
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (current === 'system') apply('system');
  });
}

export function setThemeMode(m: ThemeMode): void {
  themeMode.set(m);
}

export function cycleTheme(): void {
  themeMode.update((m) => (m === 'system' ? 'light' : m === 'light' ? 'dark' : 'system'));
}
