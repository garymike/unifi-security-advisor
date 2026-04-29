import { describe, it, expect } from 'vitest';
import { extractSites } from '../collect.js';

describe('extractSites', () => {
  it('parses data array shape', () => expect(extractSites({ data: [{ id: 's1' }] })).toHaveLength(1));
  it('parses plain array', () => expect(extractSites([{ id: 's1' }])).toHaveLength(1));
  it('returns [] for null', () => expect(extractSites(null)).toHaveLength(0));
});
