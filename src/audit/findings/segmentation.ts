import type { Finding, NormalizedSite } from '../types.js';

export function findSegmentation(site: NormalizedSite, _profile: string): Finding[] {
  const userNets = site.networks.filter(n =>
    ['corporate', 'guest', 'vlan-only'].includes(String(n['purpose'] ?? ''))
  );
  if (userNets.length <= 1) {
    return [{
      id: `SEG-001-${site.siteId}`, section: 'Segmentation', severity: 'high', status: 'gap',
      title: 'Flat network (no segmentation)',
      currentState: `Site '${site.siteName}' has ${userNets.length} user-defined network(s). A compromise of any device can reach any other.`,
      recommendation: 'Create separate networks for main, IoT, guest, and management. Map SSIDs to VLANs. Enable Zone-Based Firewall rules.',
      intentQuestion: 'Do you want to segment the network?',
      evidence: { networkCount: userNets.length }, mapsTo: { nist_csf: 'PR.AC-5', cis_v8: '12.2' },
      effort: 'project', impact: 'high',
    }];
  }
  return [];
}
