import type { Finding, NormalizedSite } from '../types.js';

export function findFirewall(site: NormalizedSite, _profile: string): Finding[] {
  const active = site.portForwards.filter(p => p['enabled'] !== false);
  if (!active.length) return [];
  return [{
    id: `FW-${site.siteId}-PF`, section: 'Firewall', severity: 'info', status: 'recommendation',
    title: `${active.length} port forward(s) active`,
    currentState: `${active.length} port forwards expose internal services.`,
    recommendation: 'Review each. Prefer VPN for admin access; use source IP allowlists for public services.',
    intentQuestion: 'Want to review each port forward?',
    evidence: { count: active.length }, mapsTo: { cis_v8: '4.4' }, effort: 'medium', impact: 'high',
  }];
}
