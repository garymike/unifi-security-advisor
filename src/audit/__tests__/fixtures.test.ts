import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { normalizeApi } from '../normalize.js';
import { analyze } from '../analyze.js';
import type { Finding } from '../types.js';

function loadFixture(file: string): Record<string, unknown> {
  const p = path.join(process.cwd(), 'samples', file);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function run(file: string, profile: string): Finding[] {
  const raw = loadFixture(file);
  const sites = normalizeApi(raw, profile);
  return analyze(sites, raw, profile);
}

function find(findings: Finding[], prefix: string): Finding | undefined {
  return findings.find(f => f.id.startsWith(prefix));
}

describe('fixture: home (single-AP, flat network)', () => {
  const findings = run('fixture-home.json', 'home');

  it('flags the flat network as high/gap', () => {
    expect(find(findings, 'SEG-001')).toMatchObject({ severity: 'high', status: 'gap' });
  });

  it('applies the home profile override to LOG-FWD-001 (info -> low)', () => {
    expect(find(findings, 'LOG-FWD-001')).toMatchObject({ severity: 'low', status: 'unknown' });
  });

  it('flags the update-available device (recommendation), no EOL/SSH/high-TX findings', () => {
    // Device aa:10:00:00:00:01 reports firmwareUpdatable=true, so a firmware
    // update-available recommendation fires (the console's own signal, not a
    // version heuristic). Everything else is clean.
    const ver = find(findings, 'FW-VER');
    expect(ver).toMatchObject({ status: 'recommendation', severity: 'medium' });
    expect(ver!.id).toBe('FW-VER-aa:10:00:00:00:01');
    expect(find(findings, 'FW-EOL')).toBeUndefined();
    expect(find(findings, 'DEV-SSH')).toBeUndefined();
    expect(findings.some(f => f.id.includes('-TX'))).toBe(false);
  });

  it('reports the API-visibility gaps every live-mode fixture hits', () => {
    for (const prefix of ['META-COVERAGE', 'BAK-001', 'FW-CONTENT-001', 'FW-AUTO-001', 'RF-ROGUE-001']) {
      expect(find(findings, prefix), prefix).toBeDefined();
    }
  });
});

describe('fixture: small-business (multi-AP, segmented, mixed hardware age)', () => {
  const findings = run('fixture-small-business.json', 'small_business');

  it('does not flag segmentation (3 purpose-tagged networks)', () => {
    expect(find(findings, 'SEG-001')).toBeUndefined();
  });

  it('flags the EOL access point as high/gap and the EOL-warning device as medium', () => {
    expect(find(findings, 'FW-EOL-001')).toMatchObject({ severity: 'high', status: 'gap' });
    expect(find(findings, 'FW-EOL-002')).toMatchObject({ severity: 'medium', status: 'recommendation' });
  });

  it('flags a firmware-update-available device by real MAC (not "undefined")', () => {
    const f = find(findings, 'FW-VER-');
    expect(f).toBeDefined();
    expect(f!.id).not.toContain('undefined');
    expect(f).toMatchObject({ status: 'recommendation', severity: 'medium' });
  });

  it('flags high TX power on both radios by real device MAC (not "undefined")', () => {
    const txFindings = findings.filter(f => f.id.includes('-TX'));
    expect(txFindings).toHaveLength(2);
    for (const f of txFindings) expect(f.id).not.toContain('undefined');
  });

  it('flags SSH enabled on the gateway', () => {
    expect(find(findings, 'DEV-SSH')).toMatchObject({ severity: 'medium' });
  });

  it('does not apply hipaa/pci severity overrides (small_business has none)', () => {
    expect(find(findings, 'LOG-FWD-001')).toMatchObject({ severity: 'info', status: 'unknown' });
    expect(find(findings, 'BAK-001')).toMatchObject({ severity: 'info', status: 'unknown' });
  });

  it('flags the failover gateway against the known UniFi OS RCE advisory', () => {
    const adv = find(findings, 'ADV-');
    expect(adv).toMatchObject({ status: 'gap', severity: 'critical' });
    const devices = adv!.evidence['devices'] as Array<{ name: unknown }>;
    expect(devices.some(d => d.name === 'FailoverGateway')).toBe(true);
  });

  it('flags every device the controller reports as updatable, by real MAC', () => {
    // Three devices carry firmwareUpdatable=true (aa:…01/04/06); the fix keys
    // off that signal, so all three get an update-available recommendation.
    // The failover gateway (…06) is also caught by the CVE advisory check
    // separately (ADV-), which is version-precise; both correctly fire.
    const verFindings = findings.filter(f => f.id.startsWith('FW-VER-'));
    expect(verFindings).toHaveLength(3);
    expect(verFindings.map(f => f.id)).toEqual(expect.arrayContaining([
      'FW-VER-aa:20:00:00:00:01', 'FW-VER-aa:20:00:00:00:04', 'FW-VER-aa:20:00:00:00:06',
    ]));
    for (const f of verFindings) expect(f.id).not.toContain('undefined');
  });
});

describe('fixture: regulated (simulated compliance environment)', () => {
  it('regulated_hipaa escalates BAK-001 to critical and LOG-FWD-001 to high', () => {
    const findings = run('fixture-regulated.json', 'regulated_hipaa');
    expect(find(findings, 'BAK-001')).toMatchObject({ severity: 'critical', status: 'unknown' });
    expect(find(findings, 'LOG-FWD-001')).toMatchObject({ severity: 'high', status: 'unknown' });
    expect(find(findings, 'FW-GEO-IN')).toMatchObject({ severity: 'low' });
    expect(find(findings, 'SEG-001')).toBeUndefined();
  });

  it('regulated_pci escalates FW-GEO-IN to medium and LOG-FWD-001 to high, but not BAK-001', () => {
    const findings = run('fixture-regulated.json', 'regulated_pci');
    expect(find(findings, 'FW-GEO-IN')).toMatchObject({ severity: 'medium' });
    expect(find(findings, 'LOG-FWD-001')).toMatchObject({ severity: 'high' });
    expect(find(findings, 'BAK-001')).toMatchObject({ severity: 'info' });
    expect(find(findings, 'SEG-001')).toBeUndefined();
  });

  it('same underlying site data, different profile -> different severities', () => {
    const hipaa = run('fixture-regulated.json', 'regulated_hipaa');
    const pci = run('fixture-regulated.json', 'regulated_pci');
    expect(find(hipaa, 'BAK-001')!.severity).not.toBe(find(pci, 'BAK-001')!.severity);
  });
});
