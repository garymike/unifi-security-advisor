import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { normalizeApi } from '../normalize.js';
import { analyze } from '../analyze.js';

/**
 * Regression over a UniFi Network v10 live-API response, shaped from the
 * official OpenAPI spec (v10.3.58): paginated `{data:[...]}` envelopes and the
 * v10 field names (macAddress, firmwareVersion, wifi/broadcasts'
 * securityConfiguration, etc.). Proves the pipeline consumes v10 shapes without
 * throwing, that device-based findings work on live data, and — critically for
 * a security tool — that the endpoints whose v10 shapes differ from the
 * backup-oriented modules degrade to no-finding rather than false-alarming.
 *
 * These shapes are derived from the spec, not captured from live hardware; the
 * runtime version check and schema-drift check are the safety net if reality
 * differs. See docs/superpowers/specs/2026-07-03-api-currency-design.md.
 */
function loadFixture(): Record<string, unknown> {
  const p = path.join(process.cwd(), 'samples', 'fixture-local-api-v10.json');
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

describe('fixture: UniFi Network v10 live-API response (spec-shaped)', () => {
  const raw = loadFixture();
  const sites = normalizeApi(raw, 'home_office');
  const findings = analyze(sites, raw, 'home_office');

  it('normalizes one site and unwraps the paginated {data:[]} envelopes', () => {
    expect(sites).toHaveLength(1);
    expect(sites[0]!.devices.length).toBe(2);
    expect(sites[0]!.wlans.length).toBe(1);
    expect(sites[0]!.networks.length).toBe(1);
    expect(sites[0]!.vpnConfigs.length).toBe(1);
    expect(sites[0]!.firewallPolicies.length).toBe(1);
  });

  it('runs the full analyze() pipeline without throwing', () => {
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('matches a known advisory against live device firmware (macAddress/firmwareVersion)', () => {
    // d1 is a UDM-PRO on 5.1.11 (<= vulnerableThrough 5.1.12).
    const adv = findings.find(f => f.id.startsWith('ADV-'));
    expect(adv).toBeDefined();
    expect(adv!.status).toBe('gap');
  });

  it('reports the controller version as in-range (API-VERSION ok)', () => {
    const v = findings.find(f => f.id === 'API-VERSION');
    expect(v).toBeDefined();
    expect(v!.status).toBe('ok');
    expect(v!.evidence['version']).toBe('10.3.58');
  });

  it('does not false-alarm on the v10 wifi shape (security nested in securityConfiguration)', () => {
    // wifi.ts reads w.security / w.x_passphrase, which the v10 shape does not
    // expose at top level, so it must produce NO Wi-Fi finding rather than a
    // spurious "open network" / "weak PSK" alarm. WLAN security still comes
    // from backup mode until a validated v10 adapter exists.
    const wifiFindings = findings.filter(f => f.id.startsWith('WIFI-'));
    expect(wifiFindings).toEqual([]);
  });
});
