import type { Finding, NormalizedSite } from '../types.js';

export function findBackup(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  const autoBackup = site.settings['auto_backup'] as Record<string, unknown> | undefined;

  if (autoBackup === undefined) {
    findings.push({
      id: `BAK-001-${site.siteId}`, section: 'Backup', severity: 'info', status: 'unknown',
      title: 'Backup setting: cannot check via live API',
      currentState: 'Auto-backup state is not exposed by the API.',
      recommendation: 'Enable daily automatic backups, retention at least 7 days.',
      intentQuestion: 'Is automatic backup currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '11.2', nist_csf: 'PR.IP-4' }, effort: 'quick', impact: 'high',
    });
    return findings;
  }

  if (!autoBackup['enabled']) {
    findings.push({
      id: `BAK-001-${site.siteId}`, section: 'Backup', severity: 'high', status: 'gap',
      title: 'Automatic backups disabled',
      currentState: 'Controller config backups are not running automatically.',
      recommendation: 'Enable daily automatic backups, retention at least 7 days.',
      intentQuestion: null, evidence: {}, mapsTo: { cis_v8: '11.2', nist_csf: 'PR.IP-4' }, effort: 'quick', impact: 'high',
    });
    return findings;
  }

  if ((autoBackup['destination'] ?? 'local') === 'local') findings.push({
    id: `BAK-002-${site.siteId}`, section: 'Backup', severity: 'medium', status: 'gap',
    title: 'Backups stored only on the gateway itself',
    currentState: 'Auto-backups are saved only to the gateway. Gateway loss = backup loss.',
    recommendation: 'Add an off-device destination: cloud backup, SMB share, or periodic download.',
    intentQuestion: 'Which off-device option fits your setup best?',
    evidence: {}, mapsTo: { cis_v8: '11.3' }, effort: 'medium', impact: 'medium',
  });

  findings.push({
    id: `BAK-003-${site.siteId}`, section: 'Backup', severity: 'medium', status: 'unknown',
    title: 'Backup restore not verified (Schrödinger backup)',
    currentState: 'Backups are running. Without a tested restore, viability is unknown.',
    recommendation: 'Schedule a quarterly restore test.',
    intentQuestion: 'Have you ever restored this backup, and when?',
    evidence: {}, mapsTo: { cis_v8: '11.5', nist_csf: 'PR.IP-4' }, effort: 'medium', impact: 'high',
  });

  return findings;
}
