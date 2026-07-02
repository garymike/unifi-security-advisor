import { describe, it, expect } from 'vitest';
import type { Finding, NormalizedSite } from '../types.js';
import { sortFindings, applyProfileOverrides, analyze } from '../analyze.js';

function site(id: string): NormalizedSite {
  return {
    siteId: id, siteName: id,
    devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [],
    firewallZones: [], trafficRoutes: [], settings: {},
    profile: 'home_office', apiGaps: [],
  };
}

function f(id: string, severity: Finding['severity'] = 'medium'): Finding {
  return {
    id, section: 'Test', severity, status: 'gap',
    title: id, currentState: 'x', recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'medium',
  };
}

describe('sortFindings', () => {
  it('VPN-PPTP-001 floats above medium', () => {
    expect(sortFindings([f('MEDIUM-001'), f('VPN-PPTP-001', 'critical')])[0]!.id).toBe('VPN-PPTP-001');
  });
  it('SEG-001-x floats above low', () => {
    expect(sortFindings([f('LOW-001', 'low'), f('SEG-001-x', 'high')])[0]!.id).toBe('SEG-001-x');
  });
  it('site-scoped VPN-PPTP-001-<siteId> still floats above medium', () => {
    expect(sortFindings([f('MEDIUM-001'), f('VPN-PPTP-001-site-a', 'critical')])[0]!.id).toBe('VPN-PPTP-001-site-a');
  });
  it('ADV-* critical/high floats above medium', () => {
    expect(sortFindings([f('MEDIUM-001'), f('ADV-test-site-a', 'critical')])[0]!.id).toBe('ADV-test-site-a');
  });
  it('ADV-* below high severity does not float (unlike SEG-MGMT-WAN)', () => {
    expect(sortFindings([f('ADV-test-site-a', 'low'), f('HIGH-001', 'high')])[0]!.id).toBe('HIGH-001');
  });
  it('SEG-MGMT-WAN-<siteId> floats regardless of severity (site-scoped id)', () => {
    expect(sortFindings([f('MEDIUM-001'), f('SEG-MGMT-WAN-site-a', 'info')])[0]!.id).toBe('SEG-MGMT-WAN-site-a');
  });
  it('non-float sorted by severity', () => {
    expect(sortFindings([f('L', 'low'), f('H', 'high'), f('M', 'medium')]).map(x => x.id)).toEqual(['H', 'M', 'L']);
  });
});

describe('applyProfileOverrides', () => {
  it('home profile sets LOG-FWD-001 to low', () => {
    const findings = [f('LOG-FWD-001')];
    applyProfileOverrides(findings, 'home');
    expect(findings[0]!.severity).toBe('low');
  });
  it('regulated_hipaa sets BAK-001 to critical', () => {
    const findings = [f('BAK-001', 'high')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0]!.severity).toBe('critical');
  });
  it('unknown finding id unchanged', () => {
    const findings = [f('UNKNOWN-999')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0]!.severity).toBe('medium');
  });
  it('regulated_hipaa sets site-scoped BAK-001-<siteId> to critical', () => {
    const findings = [f('BAK-001-site-a', 'high')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0]!.severity).toBe('critical');
  });
  it('does not cross-match a longer id sharing the same prefix (FW-GEO-IN vs FW-GEO-INBOUND)', () => {
    const findings = [f('FW-GEO-INBOUND-site-a', 'high')];
    applyProfileOverrides(findings, 'regulated_pci');
    expect(findings[0]!.severity).toBe('high');
  });
});

describe('analyze — multi-site finding ID scoping', () => {
  it('gives each site its own finding id instead of colliding', () => {
    const findings = analyze([site('site-a'), site('site-b')], {}, 'home_office');
    const bakUnknown = findings.filter(f => f.id.startsWith('BAK-001'));
    expect(bakUnknown.map(f => f.id).sort()).toEqual(['BAK-001-site-a', 'BAK-001-site-b']);
  });
});
