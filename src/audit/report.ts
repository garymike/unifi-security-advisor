import type { Finding } from './types.js';

export function renderReport(
  findings: Finding[],
  profile: string,
  endpointsProbed: number,
  endpointErrors: number,
): string {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const lines = [
    '# UniFi Security Advisor - Live Audit Report', '',
    `**Profile:** ${profile}  `,
    `**Findings:** ${findings.length}  `,
    `**By severity:** ${JSON.stringify(counts)}`,
    '',
    `**Endpoints probed:** ${endpointsProbed}  `,
    `**Endpoint errors:** ${endpointErrors}`,
    '', '---', '',
  ];

  for (const f of findings) {
    lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`*${f.section} / ${f.id}*`, '');
    lines.push(`**Current state:** ${f.currentState}`, '');
    if (f.recommendation) lines.push(`**Recommend:** ${f.recommendation}`, '');
    if (f.intentQuestion) lines.push(`**Confirm intent:** ${f.intentQuestion}`, '');
    if (Object.keys(f.mapsTo).length) {
      lines.push(`**Maps to:** ${Object.entries(f.mapsTo).map(([k, v]) => `${k}:${v}`).join(', ')}`, '');
    }
    lines.push('---', '');
  }

  lines.push(
    '## Notes', '',
    '- All secrets replaced with length + sha256 fingerprints before output.',
    '- No API key in any output file or log.',
    '- Only GET (read-only) requests were made.',
    '- Safe to share this report.', '',
    '## Next steps', '',
    '1. **Revoke the API key** at unifi.ui.com → Site Manager → API Keys.',
    '2. Review this report and decide which findings to act on.',
  );

  return lines.join('\n');
}
