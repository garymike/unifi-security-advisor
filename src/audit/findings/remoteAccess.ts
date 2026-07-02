import type { Finding, NormalizedSite } from '../types.js';

export function findRemoteAccess(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  const vpnByType: Record<string, Record<string, unknown>> = {};
  for (const v of site.vpnConfigs) {
    if (v['enabled'] === false) continue;
    const t = String(v['type'] ?? '').toLowerCase().replace(/[-/]/g, '_');
    vpnByType[t] = v as Record<string, unknown>;
  }
  const pptp = vpnByType['pptp'];
  const l2tp = vpnByType['l2tp'] ?? vpnByType['l2tp_ipsec'];
  const wireguard = vpnByType['wireguard'] ?? vpnByType['wg'];
  const openvpn = vpnByType['openvpn'];

  if (pptp) findings.push({
    id: `VPN-PPTP-001-${site.siteId}`, section: 'Remote access', severity: 'critical', status: 'gap',
    title: 'PPTP VPN enabled (broken protocol)',
    currentState: 'PPTP is enabled. MS-CHAPv2 is cryptographically broken; credentials and traffic can be recovered by anyone on-path.',
    recommendation: 'Disable PPTP immediately. Replace with WireGuard. Rotate all credentials used over PPTP.',
    intentQuestion: null, evidence: {}, mapsTo: { cis_v8: '4.4', nist_csf: 'PR.AC-3' }, effort: 'quick', impact: 'high',
  });

  if (l2tp && !wireguard && !openvpn) findings.push({
    id: `VPN-L2TP-001-${site.siteId}`, section: 'Remote access', severity: 'medium', status: 'recommendation',
    title: 'L2TP/IPsec is the only VPN (consider WireGuard)',
    currentState: 'L2TP/IPsec is the only VPN. Often blocked by hotel/public Wi-Fi; slower than WireGuard.',
    recommendation: 'Add WireGuard as the primary VPN.',
    intentQuestion: 'Do you have a client that specifically requires L2TP?',
    evidence: {}, mapsTo: { cis_v8: '4.4' }, effort: 'medium', impact: 'medium',
  });

  const activeForwards = site.portForwards.filter(p => p['enabled'] !== false);
  if (activeForwards.length && !wireguard && !openvpn && !l2tp) findings.push({
    id: `VPN-MISSING-001-${site.siteId}`, section: 'Remote access', severity: 'high', status: 'gap',
    title: `${activeForwards.length} services exposed to internet, no VPN configured`,
    currentState: `${activeForwards.length} port forwards expose internal services. No VPN configured.`,
    recommendation: 'Set up WireGuard VPN, then remove port forwards used only for remote access.',
    intentQuestion: 'Are any port forwards for services that must be public-facing?',
    evidence: {}, mapsTo: { cis_v8: '4.4', nist_csf: 'PR.AC-3' }, effort: 'medium', impact: 'high',
  });

  if (wireguard) findings.push({
    id: `VPN-WG-OK-${site.siteId}`, section: 'Remote access', severity: 'info', status: 'ok',
    title: 'WireGuard VPN configured',
    currentState: 'WireGuard VPN is enabled. This is the recommended remote access path.',
    recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: { cis_v8: '4.4' }, effort: 'quick', impact: 'low',
  });

  return findings;
}
