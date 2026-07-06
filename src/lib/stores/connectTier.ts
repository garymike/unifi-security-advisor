import { writable } from 'svelte/store';
import type { ConnectTier } from '../onboarding/keyInstructions.js';

const KEY = 'connectTier';
const initial: ConnectTier =
  (typeof localStorage !== 'undefined' && (localStorage.getItem(KEY) as ConnectTier)) || 'guided';

export const connectTier = writable<ConnectTier>(initial);

connectTier.subscribe((v) => {
  if (typeof localStorage !== 'undefined') localStorage.setItem(KEY, v);
});
