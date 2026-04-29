export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Status = 'ok' | 'gap' | 'recommendation' | 'unknown';
export type Effort = 'quick' | 'medium' | 'project';
export type Impact = 'low' | 'medium' | 'high';

export interface TierOverrides {
  currentState?: string;
  recommendation?: string;
  intentQuestion?: string;
}

export interface Finding {
  id: string;
  section: string;
  severity: Severity;
  status: Status;
  title: string;
  currentState: string;
  recommendation: string | null;
  intentQuestion: string | null;
  evidence: Record<string, unknown>;
  mapsTo: Record<string, string>;
  effort: Effort;
  impact: Impact;
  floatTop?: boolean;
  tiers?: { guided?: TierOverrides; pro?: TierOverrides };
}

export interface NormalizedSite {
  siteId: string;
  siteName: string;
  devices: Record<string, unknown>[];
  clients: Record<string, unknown>[];
  wlans: Record<string, unknown>[];
  networks: Record<string, unknown>[];
  portForwards: Record<string, unknown>[];
  vpnConfigs: Record<string, unknown>[];
  firewallPolicies: Record<string, unknown>[];
  firewallZones: Record<string, unknown>[];
  trafficRoutes: Record<string, unknown>[];
  settings: Record<string, unknown>;
  profile: string;
  apiGaps: string[];
}

export type FindingModule = (site: NormalizedSite, profile: string) => Finding[];
