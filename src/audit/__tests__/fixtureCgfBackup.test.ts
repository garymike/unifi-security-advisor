import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { normalizeBackup } from '../normalizeBackup.js';
import { analyze } from '../analyze.js';

function loadFixture(): Record<string, Record<string, unknown>[]> {
  const p = path.join(process.cwd(), 'samples', 'fixture-cgf-backup.json');
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

describe('fixture: real Cloud Gateway Fiber console backup, decrypted', () => {
  const collections = loadFixture();
  const sites = normalizeBackup(collections, 'home_office');
  const findings = analyze(sites, {}, 'home_office');

  it('produces exactly one site (backups are single-site)', () => {
    expect(sites).toHaveLength(1);
  });

  it('has full API coverage (apiGaps is empty in backup mode)', () => {
    expect(sites[0]!.apiGaps).toHaveLength(0);
  });

  it('populates real device, network, and firewall data from the decrypted backup', () => {
    expect(sites[0]!.devices.length).toBeGreaterThan(0);
    expect(sites[0]!.networks.length).toBeGreaterThan(0);
  });

  it('runs the full analyze() pipeline without throwing and produces findings', () => {
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('evaluates SEG-MGMT-WAN with full visibility (apiGaps empty), not the live-API-unknown branch', () => {
    const seg = findings.find(f => f.id.startsWith('SEG-MGMT-WAN'));
    expect(seg).toBeDefined();
    // In backup mode apiGaps is empty, so this must NOT be the
    // "cannot check via live API" branch. Note: this fixture's field
    // projection never includes firewallrule/portforward collections at
    // all (not in FIELD_PROJECTIONS), so this doesn't exercise the
    // positive detection path (finding an actual exposure rule) -- it
    // proves backup mode correctly has full visibility and takes the
    // heuristic-evaluation path rather than falling back to "can't check."
    expect(seg!.currentState).not.toMatch(/not exposed by the Network Integration API/i);
    expect(seg!.status).toBe('unknown');
    expect(seg!.currentState).toMatch(/no firewall rule or port forward was found/i);
  });
});
