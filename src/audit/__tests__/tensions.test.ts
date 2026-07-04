import { describe, it, expect } from 'vitest';
import { detectTensions, TENSION_RULES } from '../tensions.js';
import type { Finding, Status } from '../types.js';

function finding(id: string, status: Status = 'gap'): Finding {
  return {
    id, section: 's', severity: 'high', status, title: id,
    currentState: '', recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'high',
  };
}

const SITE = 'default';

describe('detectTensions', () => {
  it('fires WAN-RCE when management is exposed AND firmware is vulnerable', () => {
    const findings = [
      finding(`SEG-MGMT-WAN-${SITE}`, 'gap'),
      finding(`ADV-CVE-2026-1-${SITE}`, 'gap'),
    ];
    const t = detectTensions(findings, SITE);
    const rce = t.find(f => f.id === `TENSION-WAN-RCE-${SITE}`);
    expect(rce).toBeDefined();
    expect(rce!.severity).toBe('critical');
    expect(rce!.evidence['contributors']).toEqual([
      `SEG-MGMT-WAN-${SITE}`,
      `ADV-CVE-2026-1-${SITE}`,
    ]);
  });

  it('does NOT fire WAN-RCE when exposure is only unknown (unconfirmed)', () => {
    const findings = [
      finding(`SEG-MGMT-WAN-${SITE}`, 'unknown'),
      finding(`ADV-CVE-2026-1-${SITE}`, 'gap'),
    ];
    expect(detectTensions(findings, SITE)).toEqual([]);
  });

  it('is answer-aware: an intent answer that clears a finding suppresses the compound', () => {
    // e.g. the user confirmed the exposed service is intentionally public →
    // mergeAnswer set SEG-MGMT-WAN to ok → the compound must not fire.
    const findings = [
      finding(`SEG-MGMT-WAN-${SITE}`, 'ok'),
      finding(`ADV-CVE-2026-1-${SITE}`, 'gap'),
    ];
    expect(detectTensions(findings, SITE)).toEqual([]);
  });

  it('fires FLAT-REMOTE for a flat network with exposed services', () => {
    const t = detectTensions(
      [finding(`SEG-001-${SITE}`), finding(`VPN-MISSING-001-${SITE}`)],
      SITE,
    );
    expect(t.some(f => f.id === `TENSION-FLAT-REMOTE-${SITE}`)).toBe(true);
  });

  it('fires BACKUP-RESILIENCE (BAK-003 may be unknown/Schrödinger)', () => {
    const t = detectTensions(
      [finding(`BAK-002-${SITE}`, 'gap'), finding(`BAK-003-${SITE}`, 'unknown')],
      SITE,
    );
    expect(t.some(f => f.id === `TENSION-BACKUP-RESILIENCE-${SITE}`)).toBe(true);
  });

  it('fires DEPRECATED-VPN-FLAT for PPTP into a flat network', () => {
    const t = detectTensions(
      [finding(`VPN-PPTP-001-${SITE}`, 'gap'), finding(`SEG-001-${SITE}`)],
      SITE,
    );
    expect(t.some(f => f.id === `TENSION-DEPRECATED-VPN-FLAT-${SITE}`)).toBe(true);
  });

  it('fires EOL-VULNERABLE for end-of-life hardware with an advisory', () => {
    const t = detectTensions(
      [finding(`FW-EOL-001-${SITE}`), finding(`ADV-CVE-2026-1-${SITE}`)],
      SITE,
    );
    expect(t.some(f => f.id === `TENSION-EOL-VULNERABLE-${SITE}`)).toBe(true);
  });

  it('fires WEAK-WIFI-FLAT for a short PSK on a flat network', () => {
    const t = detectTensions(
      [finding(`WIFI-${SITE}-HomeNet-PSK`), finding(`SEG-001-${SITE}`)],
      SITE,
    );
    expect(t.some(f => f.id === `TENSION-WEAK-WIFI-FLAT-${SITE}`)).toBe(true);
  });

  it('emits nothing when no combination holds', () => {
    expect(detectTensions([finding(`SEG-001-${SITE}`)], SITE)).toEqual([]);
    expect(detectTensions([], SITE)).toEqual([]);
  });

  it('scopes compound ids to the site', () => {
    const t = detectTensions(
      [finding('SEG-001-siteB', 'gap'), finding('VPN-MISSING-001-siteB', 'gap')],
      'siteB',
    );
    expect(t[0]!.id).toBe('TENSION-FLAT-REMOTE-siteB');
  });

  it('every rule has a unique id and required copy', () => {
    const ids = TENSION_RULES.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const r of TENSION_RULES) {
      expect(r.title.length).toBeGreaterThan(0);
      expect(r.recommendation.length).toBeGreaterThan(0);
    }
  });
});
