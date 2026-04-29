#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { UniFiClient } from './audit/client.js';
import { collectAll } from './audit/collect.js';
import { sanitize } from './audit/sanitize.js';
import { normalizeApi } from './audit/normalize.js';
import { analyze } from './audit/analyze.js';
import { renderReport } from './audit/report.js';

async function main() {
  const client = UniFiClient.fromEnv();
  const outputDir = process.env['UNIFI_OUTPUT_DIR'] ?? './audit_output';
  await mkdir(outputDir, { recursive: true });

  const log = (msg: string) => console.log(msg);

  log('='.repeat(60));
  log('UniFi Security Advisor - starting audit');
  log(`Mode: ${client.config.useCloud ? 'cloud (Site Manager)' : 'local'}`);
  if (!client.config.useCloud) log(`Host: ${client.config.host}`);
  log(`Profile: ${client.config.profile}`);
  log('='.repeat(60));

  const raw = await collectAll(client, log);
  log('Sanitizing collected data...');
  const clean = sanitize(raw) as Record<string, unknown>;

  await writeFile(join(outputDir, 'raw_sanitized.json'), JSON.stringify(clean, null, 2));
  log('Wrote raw_sanitized.json');

  log('Running findings analysis...');
  const sites = normalizeApi(clean, client.config.profile);
  if (sites.length === 0) {
    log('Warning: no sites normalized from API response. Check API key scope and controller connectivity.');
    if (client.config.useCloud) {
      log('  Cloud mode note: Site Manager API site-scoped data collection is not yet implemented (Phase 3).');
    }
  }
  const findings = analyze(sites, clean, client.config.profile, (mod, site, err) => {
    console.error(`Module ${mod} failed on ${site}: ${err}`);
  });

  await writeFile(join(outputDir, 'findings.json'), JSON.stringify(findings, null, 2));
  log(`Wrote findings.json (${findings.length} findings)`);

  const report = renderReport(
    findings,
    client.config.profile,
    (clean['_endpointsProbed'] as unknown[]).length,
    ((clean['_errors'] as unknown[]) ?? []).length,
  );
  await writeFile(join(outputDir, 'report.md'), report);
  log('Wrote report.md');

  log('='.repeat(60));
  log('Done.');
  log('NEXT STEPS');
  log('  1. Review report.md');
  log('  2. Revoke the API key in Site Manager');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
