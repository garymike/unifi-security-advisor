import { describe, it, expect } from 'vitest';
import { compareVersions } from '../compareVersions.js';

describe('compareVersions', () => {
  it('returns 0 for equal versions', () => {
    expect(compareVersions('5.0.16', '5.0.16')).toBe(0);
  });
  it('returns negative when a < b', () => {
    expect(compareVersions('5.0.15', '5.0.16')).toBeLessThan(0);
  });
  it('returns positive when a > b', () => {
    expect(compareVersions('5.0.17', '5.0.16')).toBeGreaterThan(0);
  });
  it('treats a shorter version as having trailing zero segments', () => {
    expect(compareVersions('5.1', '5.1.0')).toBe(0);
    expect(compareVersions('5.1.1', '5.1')).toBeGreaterThan(0);
  });
  it('treats non-numeric segments as 0 rather than throwing', () => {
    expect(() => compareVersions('abc', '1.0.0')).not.toThrow();
    expect(compareVersions('abc', '1.0.0')).toBeLessThan(0);
  });
  it('treats an empty string as all-zero', () => {
    expect(compareVersions('', '0.0.1')).toBeLessThan(0);
    expect(compareVersions('', '')).toBe(0);
  });
});
