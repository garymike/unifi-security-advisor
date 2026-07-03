import { describe, it, expect } from 'vitest';
import { findUncoveredKevCves } from '../../../tools/check-advisory-drift.js';
import { ADVISORIES_LAST_REVIEWED, type Advisory } from '../knownAdvisoriesData.js';

const advisories: Advisory[] = [
  {
    id: 'A',
    title: 'test',
    severity: 'critical',
    cves: ['CVE-2026-1000', 'CVE-2026-1001'],
    cisaKev: true,
    affectedModels: {},
    recommendation: 'update',
    advisoryUrl: 'https://example.invalid',
  },
];

describe('findUncoveredKevCves', () => {
  it('flags a KEV CVE that is absent from the advisory data', () => {
    const uncovered = findUncoveredKevCves(['CVE-2026-1000', 'CVE-2026-9999'], advisories);
    expect(uncovered).toEqual(['CVE-2026-9999']);
  });

  it('matches case-insensitively (KEV casing vs data casing)', () => {
    const lower: Advisory[] = [{ ...advisories[0]!, cves: ['cve-2026-1000'] }];
    expect(findUncoveredKevCves(['CVE-2026-1000'], lower)).toEqual([]);
  });

  it('returns empty when every KEV CVE is covered', () => {
    expect(findUncoveredKevCves(['CVE-2026-1000', 'CVE-2026-1001'], advisories)).toEqual([]);
  });

  it('treats a CVE covered inside a multi-CVE advisory as covered', () => {
    // CVE-2026-1001 is the second entry in advisory A's cves array.
    expect(findUncoveredKevCves(['CVE-2026-1001'], advisories)).toEqual([]);
  });

  it('preserves the original casing of uncovered ids in its output', () => {
    expect(findUncoveredKevCves(['Cve-2026-Abcd'], advisories)).toEqual(['Cve-2026-Abcd']);
  });

  it('treats an acknowledged (out-of-scope) CVE as covered', () => {
    const uncovered = findUncoveredKevCves(
      ['CVE-2026-9999'],
      advisories,
      ['CVE-2026-9999'],
    );
    expect(uncovered).toEqual([]);
  });

  it('acknowledged matching is case-insensitive', () => {
    expect(findUncoveredKevCves(['CVE-2026-9999'], advisories, ['cve-2026-9999'])).toEqual([]);
  });
});

describe('ADVISORIES_LAST_REVIEWED', () => {
  it('is an ISO YYYY-MM-DD date string', () => {
    expect(ADVISORIES_LAST_REVIEWED).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
