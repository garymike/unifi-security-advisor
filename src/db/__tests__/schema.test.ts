import { describe, it, expect } from 'vitest';
import { CREATE_TABLES } from '../schema.js';

describe('CREATE_TABLES', () => {
  it('contains runs table', () => {
    expect(CREATE_TABLES.some(s => s.includes('CREATE TABLE IF NOT EXISTS runs'))).toBe(true);
  });
  it('contains findings table', () => {
    expect(CREATE_TABLES.some(s => s.includes('CREATE TABLE IF NOT EXISTS findings'))).toBe(true);
  });
  it('contains answers table', () => {
    expect(CREATE_TABLES.some(s => s.includes('CREATE TABLE IF NOT EXISTS answers'))).toBe(true);
  });
  it('contains sites table', () => {
    expect(CREATE_TABLES.some(s => s.includes('CREATE TABLE IF NOT EXISTS sites'))).toBe(true);
  });
  it('has exactly 4 tables', () => {
    expect(CREATE_TABLES).toHaveLength(4);
  });
});
