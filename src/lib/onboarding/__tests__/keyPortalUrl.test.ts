import { describe, it, expect } from 'vitest';
import { keyPortalUrl } from '../keyPortalUrl.js';

describe('keyPortalUrl', () => {
  it('returns the Site Manager portal for cloud', () => {
    expect(keyPortalUrl('cloud')).toBe('https://unifi.ui.com');
  });
  it('builds the local Network app URL from a bare host', () => {
    expect(keyPortalUrl('local', '192.168.1.1')).toBe('https://192.168.1.1/network/');
  });
  it('respects a host that already has a scheme and trims trailing slashes', () => {
    expect(keyPortalUrl('local', 'https://udm.local/')).toBe('https://udm.local/network/');
  });
  it('returns null for local with no host yet', () => {
    expect(keyPortalUrl('local')).toBeNull();
    expect(keyPortalUrl('local', '   ')).toBeNull();
  });
});
