import { describe, it, expect } from 'vitest';
import { extractSites, buildConnectorUrl } from '../collect.js';

describe('extractSites', () => {
  it('parses data array shape', () => expect(extractSites({ data: [{ id: 's1' }] })).toHaveLength(1));
  it('parses plain array', () => expect(extractSites([{ id: 's1' }])).toHaveLength(1));
  it('returns [] for null', () => expect(extractSites(null)).toHaveLength(0));
});

describe('buildConnectorUrl', () => {
  it('builds the correct Cloud Connector URL', () => {
    expect(buildConnectorUrl('abc123', 'default', 'devices'))
      .toBe('https://api.ui.com/v1/connector/consoles/abc123/proxy/network/integration/v1/sites/default/devices');
  });

  it('handles hyphenated resource names', () => {
    expect(buildConnectorUrl('abc123', 'default', 'firewall-policies'))
      .toBe('https://api.ui.com/v1/connector/consoles/abc123/proxy/network/integration/v1/sites/default/firewall-policies');
  });

  it('resource segment extracted from SITE_SCOPED path template', () => {
    const pathTpl = '/proxy/network/integration/v1/sites/{id}/vpn-configs';
    expect(pathTpl.split('/').at(-1)).toBe('vpn-configs');
  });
});
