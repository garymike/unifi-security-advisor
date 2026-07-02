import type { Finding, NormalizedSite } from '../types.js';
import { EOL_MODELS } from '../constants.js';

export function findFirmware(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];

  const autoUpdate = site.settings['auto_update'] as Record<string, unknown> | undefined;
  if (autoUpdate === undefined) {
    findings.push({
      id: `FW-AUTO-001-${site.siteId}`, section: 'Firmware', severity: 'info', status: 'unknown',
      title: 'Auto-update setting: cannot check via live API',
      currentState: 'Auto-update state is not exposed by the API. Check Settings → System → Updates.',
      recommendation: 'Enable automatic firmware updates in a maintenance window (e.g. 03:00–05:00).',
      intentQuestion: 'Is automatic firmware update enabled?',
      evidence: {}, mapsTo: { cis_v8: '7.3', nist_csf: 'PR.IP-12' }, effort: 'quick', impact: 'medium',
    });
  } else if (!autoUpdate['enabled']) {
    findings.push({
      id: `FW-AUTO-001-${site.siteId}`, section: 'Firmware', severity: 'medium', status: 'gap',
      title: 'Automatic firmware updates disabled',
      currentState: 'Devices do not auto-update firmware.',
      recommendation: 'Enable automatic firmware updates in a maintenance window.',
      intentQuestion: 'Any reason to hold back updates?',
      evidence: {}, mapsTo: { cis_v8: '7.3', nist_csf: 'PR.IP-12' }, effort: 'quick', impact: 'medium',
    });
  }

  const eolDevices: Record<string, unknown>[] = [];
  for (const d of site.devices) {
    const model = String(d['model'] ?? '').toUpperCase();
    if (model in EOL_MODELS) eolDevices.push({ ...EOL_MODELS[model]!, name: d['name'] ?? d['mac'] ?? d['macAddress'], model });
  }

  const eolCount = eolDevices.filter(d => d['status'] === 'eol').length;
  const warnCount = eolDevices.filter(d => d['status'] === 'eol_warning').length;

  if (eolCount) findings.push({
    id: `FW-EOL-001-${site.siteId}`, section: 'Firmware', severity: 'high', status: 'gap',
    title: `${eolCount} device(s) past end-of-support`,
    currentState: `${eolCount} device(s) are past Ubiquiti's end-of-support date and no longer receive security patches.`,
    recommendation: 'Plan replacement. Prioritise internet-facing devices first.',
    intentQuestion: 'What is your replacement budget and timeline?',
    evidence: { devices: eolDevices.filter(d => d['status'] === 'eol') },
    mapsTo: { cis_v8: '7.3', nist_csf: 'PR.IP-12' }, effort: 'project', impact: 'high',
  });

  if (warnCount) findings.push({
    id: `FW-EOL-002-${site.siteId}`, section: 'Firmware', severity: 'medium', status: 'recommendation',
    title: `${warnCount} device(s) approaching EOL`,
    currentState: `${warnCount} device(s) reach end-of-support within 12 months.`,
    recommendation: 'Start planning replacements during your normal refresh cycle.',
    intentQuestion: 'Is hardware refresh on your roadmap?',
    evidence: { devices: eolDevices.filter(d => d['status'] === 'eol_warning') },
    mapsTo: { cis_v8: '7.3' }, effort: 'project', impact: 'medium',
  });

  for (const d of site.devices) {
    const mac = d['mac'] ?? d['macAddress'];
    const ver = String(d['version'] ?? d['firmwareVersion'] ?? '');
    if (ver.includes('.')) {
      const major = parseInt(ver.split('.')[0]!, 10);
      if (!isNaN(major) && major < 7) findings.push({
        id: `FW-VER-${mac ?? 'x'}`, section: 'Firmware', severity: 'high', status: 'gap',
        title: `Device '${d['name'] ?? mac}' on outdated major version`,
        currentState: `Firmware ${ver} is multiple major versions behind current.`,
        recommendation: 'Update to latest stable firmware in a maintenance window.',
        intentQuestion: null, evidence: {}, mapsTo: { cis_v8: '7.3' }, effort: 'quick', impact: 'high',
      });
    }
  }

  return findings;
}
