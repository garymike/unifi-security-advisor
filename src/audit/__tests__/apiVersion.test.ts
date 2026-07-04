import { describe, it, expect } from 'vitest';
import {
  parseApplicationVersion,
  assessVersion,
  TESTED_MIN,
  TESTED_MAX,
} from '../apiVersion.js';
import { findApiVersion } from '../findings/apiVersion.js';

describe('parseApplicationVersion', () => {
  it('reads the bare { applicationVersion } shape', () => {
    expect(parseApplicationVersion({ applicationVersion: '10.3.58' })).toBe('10.3.58');
  });

  it('reads a { data: { applicationVersion } } envelope', () => {
    expect(parseApplicationVersion({ data: { applicationVersion: '9.4.19' } })).toBe('9.4.19');
  });

  it('returns null for missing / non-object / empty', () => {
    expect(parseApplicationVersion(null)).toBeNull();
    expect(parseApplicationVersion({})).toBeNull();
    expect(parseApplicationVersion({ applicationVersion: '' })).toBeNull();
    expect(parseApplicationVersion('10.3.58')).toBeNull();
  });
});

describe('assessVersion', () => {
  it('classifies a version inside the tested range as ok', () => {
    expect(assessVersion('10.0.0').status).toBe('ok');
    expect(assessVersion(TESTED_MIN).status).toBe('ok');
    expect(assessVersion(TESTED_MAX).status).toBe('ok');
  });

  it('flags a version newer than TESTED_MAX', () => {
    expect(assessVersion('10.4.0').status).toBe('newer-than-tested');
    expect(assessVersion('11.0.0').status).toBe('newer-than-tested');
  });

  it('flags a version older than TESTED_MIN', () => {
    expect(assessVersion('8.5.0').status).toBe('older-than-min');
  });

  it('returns unknown for null / non-version strings', () => {
    expect(assessVersion(null).status).toBe('unknown');
    expect(assessVersion('unknown').status).toBe('unknown');
  });
});

describe('findApiVersion', () => {
  it('emits nothing when there is no /info (backup/cloud mode)', () => {
    expect(findApiVersion({})).toEqual([]);
  });

  it('emits an info/ok finding for an in-range version', () => {
    const [f] = findApiVersion({ info: { applicationVersion: '10.3.58' } });
    expect(f).toBeDefined();
    expect(f!.id).toBe('API-VERSION');
    expect(f!.severity).toBe('info');
    expect(f!.status).toBe('ok');
    expect(f!.recommendation).toBeNull();
    expect(f!.evidence['version']).toBe('10.3.58');
  });

  it('raises a low/recommendation finding for a newer-than-tested version', () => {
    const [f] = findApiVersion({ info: { applicationVersion: '11.0.0' } });
    expect(f!.severity).toBe('low');
    expect(f!.status).toBe('recommendation');
    expect(f!.recommendation).toBeTruthy();
    expect(f!.evidence['status']).toBe('newer-than-tested');
  });
});
