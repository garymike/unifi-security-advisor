import type { NormalizedSite } from '../audit/types.js';

const AP_TYPE_PREFIXES = ['uap', 'u6', 'u7'];

function countAps(sites: NormalizedSite[]): number {
  return sites.flatMap(s => s.devices).filter(d => {
    const t = String(d['type'] ?? '').toLowerCase();
    return AP_TYPE_PREFIXES.some(prefix => t.startsWith(prefix));
  }).length;
}

export function inferProfile(sites: NormalizedSite[]): string {
  if (!sites.length) return 'home_office';
  const aps = countAps(sites);
  const networks = sites.flatMap(s => s.networks).length;
  if (aps <= 2 && networks <= 2) return 'home';
  if (aps <= 5 && networks <= 4) return 'home_office';
  return 'small_business';
}

export function profileLabel(profile: string): string {
  const labels: Record<string, string> = {
    home: 'Home',
    home_office: 'Home Office',
    small_business: 'Small Business',
    regulated_hipaa: 'Regulated (HIPAA)',
    regulated_pci: 'Regulated (PCI)',
  };
  return labels[profile] ?? profile;
}

export const ALL_PROFILES = [
  'home', 'home_office', 'small_business', 'regulated_hipaa', 'regulated_pci',
] as const;

export type ProfileId = typeof ALL_PROFILES[number];
