import type { Finding, NormalizedSite } from '../types.js';

export function findWifi(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  for (const w of site.wlans) {
    if (w['enabled'] === false) continue;
    const name = String(w['name'] ?? '<unnamed>');
    const security = String(w['security'] ?? w['securityProtocol'] ?? '').toLowerCase();
    const isWpa = security.startsWith('wpa') || security === 'wpapsk';
    if (isWpa && !security.includes('wpa3')) {
      findings.push({
        id: `WIFI-${site.siteId}-${name}-WPA`, section: 'Wi-Fi', severity: 'low', status: 'recommendation',
        title: `SSID '${name}' is WPA2-only`,
        currentState: `SSID '${name}' uses WPA2. WPA3 or mixed mode offers stronger protection.`,
        recommendation: 'Switch to WPA2/WPA3 mixed mode, or WPA3-only if all clients support it.',
        intentQuestion: `Do any clients on '${name}' require WPA2-only?`,
        evidence: {}, mapsTo: { cis_v8: '12.5' }, effort: 'quick', impact: 'low',
      });
    }
    const psk = w['x_passphrase'] as Record<string, unknown> | undefined;
    if (psk && typeof psk['length'] === 'number' && psk['length'] < 12) {
      findings.push({
        id: `WIFI-${site.siteId}-${name}-PSK`, section: 'Wi-Fi', severity: 'high', status: 'gap',
        title: `SSID '${name}' has a short passphrase`,
        currentState: `Passphrase is ${psk['length']} characters. Short PSKs are vulnerable to offline attacks.`,
        recommendation: 'Use a passphrase of at least 16 characters with mixed case, numbers, and symbols.',
        intentQuestion: null, evidence: {}, mapsTo: { cis_v8: '5.2' }, effort: 'quick', impact: 'high',
      });
    }
  }
  return findings;
}
