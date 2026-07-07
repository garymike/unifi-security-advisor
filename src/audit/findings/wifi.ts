import type { Finding, NormalizedSite } from '../types.js';

/**
 * Resolves an SSID's security mode across the shapes we consume. Backup mode
 * exposes a flat `security` / `securityProtocol` string (e.g. `wpapsk`, `open`);
 * the live v10 API nests it as `securityConfiguration.type` with values like
 * `WPA2_PERSONAL`, `WPA2_WPA3_PERSONAL`, `OPEN`, `WPA2_ENTERPRISE`. Returns a
 * lowercased string so callers can substring-match uniformly.
 */
function resolveSecurity(w: Record<string, unknown>): string {
  const secConfig = w['securityConfiguration'] as Record<string, unknown> | undefined;
  return String(w['security'] ?? w['securityProtocol'] ?? secConfig?.['type'] ?? '').toLowerCase();
}

export function findWifi(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  for (const w of site.wlans) {
    if (w['enabled'] === false) continue;
    const name = String(w['name'] ?? '<unnamed>');
    const security = resolveSecurity(w);

    if (security === 'open' || security === 'none') {
      findings.push({
        id: `WIFI-${site.siteId}-${name}-OPEN`, section: 'Wi-Fi', severity: 'high', status: 'gap',
        title: `SSID '${name}' is open (no encryption)`,
        currentState: `SSID '${name}' has no encryption. Anyone in range can join it, and traffic on it is unprotected.`,
        recommendation: 'Enable WPA2/WPA3 with a strong passphrase. If it must stay open (captive-portal guest access), isolate it on its own VLAN with client isolation.',
        intentQuestion: `Is '${name}' an intentional open/guest network with a captive portal?`,
        evidence: {}, mapsTo: { cis_v8: '12.6', nist_csf: 'PR.AC-3' }, effort: 'quick', impact: 'high',
      });
      continue;
    }

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
