import { describe, it, expect } from 'vitest';
import { getInstructions, type ConnectMode, type ConnectTier } from '../keyInstructions.js';

const MODES: ConnectMode[] = ['local', 'cloud'];
const TIERS: ConnectTier[] = ['guided', 'standard', 'pro'];

describe('getInstructions', () => {
  it('has a non-empty block for every mode × tier', () => {
    for (const mode of MODES) {
      for (const tier of TIERS) {
        const block = getInstructions(mode, tier);
        expect(block.steps.length, `${mode}/${tier} steps`).toBeGreaterThan(0);
        expect(block.steps.every(s => s.trim().length > 0)).toBe(true);
        expect(block.note.trim().length, `${mode}/${tier} note`).toBeGreaterThan(0);
      }
    }
  });
  it('local instructions mention Integrations; cloud mention the API section', () => {
    expect(getInstructions('local', 'pro').steps.join(' ')).toMatch(/Integrations/i);
    expect(getInstructions('cloud', 'guided').steps.join(' ')).toMatch(/unifi\.ui\.com/i);
  });
  it('every note carries the shortest-expiration / revoke guidance', () => {
    for (const mode of MODES) for (const tier of TIERS) {
      expect(getInstructions(mode, tier).note).toMatch(/shortest|revoke/i);
    }
  });
});
