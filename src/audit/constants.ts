import type { Finding } from './types.js';

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

export const ALWAYS_TOP_PREDICATES: Array<(f: Finding) => boolean> = [
  (f) => f.id.startsWith('MFA-'),
  (f) => f.id === 'SEG-MGMT-WAN',
  (f) => f.id.startsWith('SEG-001'),
  (f) => f.id.startsWith('CRED-DEFAULT'),
  (f) => f.id.startsWith('FW-EOL') && (f.severity === 'high' || f.severity === 'critical'),
  (f) => f.id === 'VPN-PPTP-001',
];

export const PROFILE_OVERRIDES: Record<string, Record<string, Partial<Finding>>> = {
  home: {
    'LOG-FWD-001': { severity: 'low' },
    'LOG-PRIV-001': { severity: 'medium' },
  },
  regulated_hipaa: {
    'LOG-FWD-001': { severity: 'high' },
    'BAK-001': { severity: 'critical' },
  },
  regulated_pci: {
    'LOG-FWD-001': { severity: 'high' },
    'FW-GEO-IN': { severity: 'medium' },
  },
};

export const EOL_MODELS: Record<string, { status: string; eolDate: string }> = {
  'UAP-AC-LITE': { status: 'eol', eolDate: '2024-04-30' },
  'UAP-AC-LR':   { status: 'eol', eolDate: '2024-04-30' },
  'UAP-AC-PRO':  { status: 'eol', eolDate: '2024-04-30' },
  'USG':         { status: 'eol', eolDate: '2024-04-30' },
  'USG-PRO-4':   { status: 'eol', eolDate: '2025-04-30' },
  'UCK':         { status: 'eol', eolDate: '2022-12-31' },
  'UCK-G2':      { status: 'eol_warning', eolDate: '2026-12-31' },
};
