import type { Finding, NormalizedSite } from '../types.js';

const MGMT_PORTS = new Set([22, 443, 8443]);

function hasGeoPolicy(policies: Record<string, unknown>[], directionHint: string): boolean {
  for (const p of policies) {
    if (p['enabled'] === false || p['action'] !== 'drop') continue;
    const src = (p['source'] ?? {}) as Record<string, unknown>;
    if (!src['geo']) continue;
    const dir = String(p['direction'] ?? '').toUpperCase();
    const name = String(p['name'] ?? '').toLowerCase();
    if (dir.includes(directionHint) || name.includes(directionHint.toLowerCase())) return true;
  }
  return false;
}

function extractPort(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  const n = parseInt(String(value), 10);
  return Number.isNaN(n) ? undefined : n;
}

/**
 * Heuristic, unverified against a real backup capture (see task notes).
 * Looks for a WAN_LOCAL-ruleset firewall rule (traffic to the gateway
 * itself, not passing through to LAN) that's enabled, accepts, has an
 * unrestricted source, and targets a management port.
 */
function hasWanLocalManagementExposure(policies: Record<string, unknown>[]): boolean {
  for (const p of policies) {
    if (p['enabled'] === false) continue;
    const action = String(p['action'] ?? '').toLowerCase();
    if (action !== 'accept') continue;
    const ruleset = String(p['ruleset'] ?? p['rule_set'] ?? '').toUpperCase();
    if (!ruleset.includes('WAN_LOCAL') && !ruleset.includes('WAN-LOCAL')) continue;
    const src = (p['source'] ?? {}) as Record<string, unknown>;
    const srcType = String(src['type'] ?? src['ip_group_type'] ?? 'any').toLowerCase();
    if (srcType !== 'any' && srcType !== '') continue;
    const port = extractPort(p['dst_port'] ?? p['dstPort'] ?? (p['destination'] as Record<string, unknown> | undefined)?.['port']);
    if (port === undefined || MGMT_PORTS.has(port)) return true;
  }
  return false;
}

/** Heuristic, unverified: a port forward whose destination port is a management port. */
function hasWanForwardToManagementPort(portForwards: Record<string, unknown>[]): boolean {
  for (const p of portForwards) {
    if (p['enabled'] === false) continue;
    const port = extractPort(p['dst_port'] ?? p['fwd_port'] ?? p['destinationPort']);
    if (port !== undefined && MGMT_PORTS.has(port)) return true;
  }
  return false;
}

function findMgmtWanExposure(site: NormalizedSite): Finding {
  const id = `SEG-MGMT-WAN-${site.siteId}`;
  const mapsTo = { cis_v8: '4.4', nist_csf: 'PR.AC-3' };
  const noVisibility = site.apiGaps.includes('firewall_policies') && site.apiGaps.includes('port_forwards');

  if (noVisibility) {
    return {
      id, section: 'Segmentation', severity: 'info', status: 'unknown',
      title: 'Management plane WAN exposure: cannot check via live API',
      currentState: 'Firewall and port-forward rules are not exposed by the Network Integration API v1, so WAN-reachability of the admin UI cannot be determined automatically.',
      recommendation: 'Manually verify: Settings → System → Remote Access. Confirm the admin UI (port 443) and SSH (port 22) are not directly reachable from the internet.',
      intentQuestion: 'Is your UniFi console\'s management UI reachable directly from the internet (not via Ubiquiti\'s official remote-access/cloud feature)?',
      evidence: {}, mapsTo, effort: 'quick', impact: 'high',
    };
  }

  const exposed = hasWanLocalManagementExposure(site.firewallPolicies) || hasWanForwardToManagementPort(site.portForwards);
  if (exposed) {
    return {
      id, section: 'Segmentation', severity: 'critical', status: 'gap',
      title: 'Management plane appears reachable from WAN',
      currentState: 'A firewall rule or port forward appears to allow inbound WAN traffic directly to a management port (SSH/HTTPS admin UI). This is the exposure path used by recent actively-exploited UniFi OS vulnerabilities.',
      recommendation: 'Remove the WAN-facing rule. Use Ubiquiti\'s official remote-access feature or a VPN for remote admin access instead of direct exposure.',
      intentQuestion: 'Is this intentional (e.g. a documented, source-restricted admin access path)?',
      evidence: { heuristic: 'WAN_LOCAL accept rule or port-forward targeting a management port; unverified against a real backup capture' },
      mapsTo, effort: 'quick', impact: 'high',
    };
  }

  return {
    id, section: 'Segmentation', severity: 'info', status: 'unknown',
    title: 'Management plane WAN exposure: no obvious exposure found, please confirm',
    currentState: 'No firewall rule or port forward was found that obviously exposes the management UI to the WAN, based on a best-effort heuristic check.',
    recommendation: 'Manually verify: Settings → System → Remote Access. Confirm the admin UI is not directly reachable from the internet.',
    intentQuestion: 'Have you manually confirmed the admin UI is not reachable directly from the internet?',
    evidence: {}, mapsTo, effort: 'quick', impact: 'high',
  };
}

export function findFirewallThreats(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];

  if (!hasGeoPolicy(site.firewallPolicies, 'WAN_IN')) findings.push({
    id: `FW-GEO-IN-${site.siteId}`, section: 'Firewall', severity: 'low', status: 'recommendation',
    title: 'No Geo-IP blocking on inbound WAN',
    currentState: 'No policy found blocking inbound traffic from high-risk regions.',
    recommendation: 'Block inbound from CN, RU, KP, IR.',
    intentQuestion: 'Do you expect inbound traffic from these regions?',
    evidence: {}, mapsTo: { cis_v8: '13.4' }, effort: 'quick', impact: 'medium',
  });

  if (!hasGeoPolicy(site.firewallPolicies, 'WAN_OUT')) findings.push({
    id: `FW-GEO-OUT-${site.siteId}`, section: 'Firewall', severity: 'low', status: 'recommendation',
    title: 'No Geo-IP blocking on outbound WAN (often overlooked)',
    currentState: 'No outbound Geo-IP policy. A compromised device could call home to a C2.',
    recommendation: 'Apply outbound geo-blocking for the same regions you block inbound.',
    intentQuestion: 'Do any of your services legitimately talk to servers in high-risk regions?',
    evidence: {}, mapsTo: { cis_v8: '13.4' }, effort: 'quick', impact: 'low',
  });

  const dnsFilter = site.settings['dns_filtering'] as Record<string, unknown> | undefined;
  if (dnsFilter === undefined) {
    findings.push({
      id: `FW-CONTENT-001-${site.siteId}`, section: 'Firewall', severity: 'info', status: 'unknown',
      title: 'Content filtering: cannot check via live API',
      currentState: 'DNS content filtering state is not exposed by the API.',
      recommendation: 'Enable Content Filtering with the Security category at minimum.',
      intentQuestion: 'Is DNS content filtering currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '9.3', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'medium',
    });
  } else if (!dnsFilter['enabled']) {
    findings.push({
      id: `FW-CONTENT-001-${site.siteId}`, section: 'Firewall', severity: 'medium', status: 'recommendation',
      title: 'Content filtering not configured',
      currentState: 'DNS-based content filtering is off.',
      recommendation: 'Enable Content Filtering with the Security category at minimum.',
      intentQuestion: 'Should the network block known-malicious domains automatically?',
      evidence: {}, mapsTo: { cis_v8: '9.3', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'medium',
    });
  }

  findings.push(findMgmtWanExposure(site));

  return findings;
}
