import type { Finding, NormalizedSite } from '../types.js';

function hasGeoPolicy(policies: Record<string, unknown>[], directionHint: string): boolean {
  for (const p of policies) {
    if (p['enabled'] === false || p['action'] !== 'drop') continue;
    const src = (p['source'] ?? {}) as Record<string, unknown>;
    if (!src['geo']) continue;
    const dir = String(p['direction'] ?? '').toUpperCase();
    const name = String(p['name'] ?? '').toLowerCase();
    if (dir.includes(directionHint) || directionHint.toLowerCase() in name) return true;
  }
  return false;
}

export function findFirewallThreats(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];

  if (!hasGeoPolicy(site.firewallPolicies, 'WAN_IN')) findings.push({
    id: 'FW-GEO-IN', section: 'Firewall', severity: 'low', status: 'recommendation',
    title: 'No Geo-IP blocking on inbound WAN',
    currentState: 'No policy found blocking inbound traffic from high-risk regions.',
    recommendation: 'Block inbound from CN, RU, KP, IR.',
    intentQuestion: 'Do you expect inbound traffic from these regions?',
    evidence: {}, mapsTo: { cis_v8: '13.4' }, effort: 'quick', impact: 'medium',
  });

  if (!hasGeoPolicy(site.firewallPolicies, 'WAN_OUT')) findings.push({
    id: 'FW-GEO-OUT', section: 'Firewall', severity: 'low', status: 'recommendation',
    title: 'No Geo-IP blocking on outbound WAN (often overlooked)',
    currentState: 'No outbound Geo-IP policy. A compromised device could call home to a C2.',
    recommendation: 'Apply outbound geo-blocking for the same regions you block inbound.',
    intentQuestion: 'Do any of your services legitimately talk to servers in high-risk regions?',
    evidence: {}, mapsTo: { cis_v8: '13.4' }, effort: 'quick', impact: 'low',
  });

  const dnsFilter = site.settings['dns_filtering'] as Record<string, unknown> | undefined;
  if (dnsFilter === undefined) {
    findings.push({
      id: 'FW-CONTENT-001', section: 'Firewall', severity: 'info', status: 'unknown',
      title: 'Content filtering: cannot check via live API',
      currentState: 'DNS content filtering state is not exposed by the API.',
      recommendation: 'Enable Content Filtering with the Security category at minimum.',
      intentQuestion: 'Is DNS content filtering currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '9.3', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'medium',
    });
  } else if (!dnsFilter['enabled']) {
    findings.push({
      id: 'FW-CONTENT-001', section: 'Firewall', severity: 'medium', status: 'recommendation',
      title: 'Content filtering not configured',
      currentState: 'DNS-based content filtering is off.',
      recommendation: 'Enable Content Filtering with the Security category at minimum.',
      intentQuestion: 'Should the network block known-malicious domains automatically?',
      evidence: {}, mapsTo: { cis_v8: '9.3', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'medium',
    });
  }

  return findings;
}
