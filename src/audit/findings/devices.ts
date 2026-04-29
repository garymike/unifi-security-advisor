import type { Finding, NormalizedSite } from '../types.js';

export function findDevices(site: NormalizedSite, _profile: string): Finding[] {
  const sshOn = site.devices.filter(d => d['sshEnabled'] || d['ssh_enabled']);
  if (!sshOn.length) return [];
  return [{
    id: `DEV-SSH-${site.siteId}`, section: 'Admin', severity: 'medium', status: 'recommendation',
    title: `SSH enabled on ${sshOn.length} device(s)`,
    currentState: `SSH is enabled on ${sshOn.length} device(s). This is a remote admin surface.`,
    recommendation: 'Disable SSH unless actively used. If needed, key-based auth only, scoped to management VLAN.',
    intentQuestion: 'Do you use SSH to these devices?',
    evidence: {}, mapsTo: { cis_v8: '4.6' }, effort: 'quick', impact: 'medium',
  }];
}
