import type { Finding, NormalizedSite } from '../types.js';

export function findWirelessTuning(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  const aps = site.devices.filter(d => d['type'] === 'uap');

  for (const d of aps) {
    const apName = String(d['name'] ?? d['mac'] ?? 'unnamed');
    for (const r of (d['radio_table'] as Record<string, unknown>[] ?? [])) {
      const band = String(r['radio'] ?? 'unknown');
      const bandLabel = ({ ng: '2.4 GHz', na: '5 GHz', '6e': '6 GHz' } as Record<string, string>)[band] ?? band;
      if (r['tx_power_mode'] === 'high') {
        findings.push({
          id: `RF-${d['mac']}-${band}-TX`, section: 'Wireless tuning', severity: 'low', status: 'recommendation',
          title: `AP '${apName}' broadcasting at High power on ${bandLabel}`,
          currentState: `AP '${apName}' ${bandLabel} radio is set to High TX power. High power extends coverage past your physical space.`,
          recommendation: 'Set TX power to Auto or Medium for typical indoor use.',
          intentQuestion: 'Is extended coverage deliberate (outdoor, large property)?',
          evidence: {}, mapsTo: { cis_v8: '12.5', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'low',
        });
      }
    }
  }

  const apsWith24 = aps.filter(d =>
    (d['radio_table'] as Record<string, unknown>[] ?? []).some(r => r['radio'] === 'ng' && !r['disabled'])
  );
  if (apsWith24.length) {
    const clientsOn24 = site.clients.filter(c => c['radio'] === 'ng').length;
    const totalWifi = site.clients.filter(c => c['radio']).length;
    findings.push({
      id: `RF-BAND-24GHZ-${site.siteId}`, section: 'Wireless tuning', severity: 'info', status: 'recommendation',
      title: '2.4 GHz radio active across AP(s)',
      currentState: `${apsWith24.length} AP(s) have 2.4 GHz enabled. ${clientsOn24} of ${totalWifi} clients are on 2.4 GHz.`,
      recommendation: 'Identify which devices need 2.4 GHz. Disable if few do to shrink attack surface.',
      intentQuestion: 'Do you have devices that truly require 2.4 GHz?',
      evidence: { apsWith24: apsWith24.length, clientsOn24, totalWifi },
      mapsTo: { cis_v8: '12.5' }, effort: 'medium', impact: 'medium',
    });
  }

  const rogueSetting = site.settings['rogueap'] as Record<string, unknown> | undefined;
  if (rogueSetting === undefined) {
    findings.push({
      id: `RF-ROGUE-001-${site.siteId}`, section: 'Wireless tuning', severity: 'info', status: 'unknown',
      title: 'Rogue AP detection: cannot check via live API',
      currentState: 'Rogue AP detection state is not exposed by the Network Integration API. Use backup-file mode or check Settings → WiFi → Advanced.',
      recommendation: 'Enable Rogue AP Detection in Settings → WiFi → Advanced.',
      intentQuestion: 'Is rogue AP detection currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '12.6', nist_csf: 'DE.CM-7' }, effort: 'quick', impact: 'medium',
    });
  } else if (!rogueSetting['report_rogue']) {
    findings.push({
      id: `RF-ROGUE-001-${site.siteId}`, section: 'Wireless tuning', severity: 'medium', status: 'gap',
      title: 'Rogue AP detection not enabled',
      currentState: 'Rogue AP reporting is disabled.',
      recommendation: 'Enable Rogue AP Detection in Settings → WiFi → Advanced.',
      intentQuestion: 'Want rogue AP detection on? (no performance cost)',
      evidence: {}, mapsTo: { cis_v8: '12.6', nist_csf: 'DE.CM-7' }, effort: 'quick', impact: 'medium',
    });
  }

  for (const w of site.wlans) {
    if (w['enabled'] === false) continue;
    const name = String(w['name'] ?? '<unnamed>');
    const wpaMode = String(w['wpa_mode'] ?? '').toLowerCase();
    const pmf = String(w['pmf_mode'] ?? 'disabled');
    if (wpaMode.includes('wpa3') && pmf === 'disabled') {
      findings.push({
        id: `RF-PMF-${name}`, section: 'Wireless tuning', severity: 'medium', status: 'gap',
        title: `SSID '${name}' uses WPA3 but PMF is disabled`,
        currentState: `SSID '${name}' has WPA3 but PMF (802.11w) is off. PMF blocks deauth attacks.`,
        recommendation: `Set PMF to Required on '${name}'.`,
        intentQuestion: null,
        evidence: {}, mapsTo: { cis_v8: '12.5' }, effort: 'quick', impact: 'medium',
      });
    }
  }

  return findings;
}
