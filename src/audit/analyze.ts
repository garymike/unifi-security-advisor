import type { Finding, FindingModule, NormalizedSite } from './types.js';
import { SEVERITY_ORDER, ALWAYS_TOP_PREDICATES, PROFILE_OVERRIDES } from './constants.js';
import { findSegmentation } from './findings/segmentation.js';
import { findWifi } from './findings/wifi.js';
import { findFirewall } from './findings/firewall.js';
import { findRemoteAccess } from './findings/remoteAccess.js';
import { findDevices } from './findings/devices.js';
import { findWirelessTuning } from './findings/wirelessTuning.js';
import { findFirewallThreats } from './findings/firewallThreats.js';
import { findFirmware } from './findings/firmware.js';
import { findLogging } from './findings/logging.js';
import { findBackup } from './findings/backup.js';
import { findApiCoverage } from './findings/apiCoverage.js';
import { findKnownAdvisories } from './findings/knownAdvisories.js';

const MODULES: Array<[string, FindingModule]> = [
  ['segmentation',    findSegmentation],
  ['wifi',            findWifi],
  ['firewall',        findFirewall],
  ['remoteAccess',    findRemoteAccess],
  ['devices',         findDevices],
  ['wirelessTuning',  findWirelessTuning],
  ['firewallThreats', findFirewallThreats],
  ['knownAdvisories', findKnownAdvisories],
  ['firmware',        findFirmware],
  ['logging',         findLogging],
  ['backup',          findBackup],
];

export function isFloatTop(f: Finding): boolean {
  return ALWAYS_TOP_PREDICATES.some(pred => pred(f));
}

export function sortFindings(findings: Finding[]): Finding[] {
  const top = findings.filter(isFloatTop)
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  const rest = findings.filter(f => !isFloatTop(f))
    .sort((a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5) ||
      a.section.localeCompare(b.section)
    );
  return [...top, ...rest];
}

export function applyProfileOverrides(findings: Finding[], profile: string): void {
  const overrides = PROFILE_OVERRIDES[profile] ?? {};
  for (const f of findings) {
    const key = Object.keys(overrides).find(k => f.id === k || f.id.startsWith(`${k}-`));
    if (key) Object.assign(f, overrides[key]);
  }
}

export function analyze(
  sites: NormalizedSite[],
  clean: Record<string, unknown>,
  profile: string,
  onError?: (module: string, site: string, err: unknown) => void,
): Finding[] {
  const findings: Finding[] = [];
  for (const site of sites) {
    for (const [name, fn] of MODULES) {
      try {
        findings.push(...fn(site, profile));
      } catch (err) {
        onError?.(name, site.siteId, err);
      }
    }
  }
  findings.push(...findApiCoverage(clean));
  applyProfileOverrides(findings, profile);
  for (const f of findings) {
    if (isFloatTop(f)) f.floatTop = true;
  }
  return sortFindings(findings);
}
