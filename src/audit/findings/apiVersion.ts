import type { Finding } from '../types.js';
import { parseApplicationVersion, assessVersion, TESTED_MIN, TESTED_MAX } from '../apiVersion.js';

/**
 * Meta-finding: reports the controller's UniFi Network version (from /v1/info)
 * and whether it's within the range this tool was verified against. Emits
 * nothing when there's no /info (backup or cloud mode). An `ok` version is an
 * informational finding; a version outside the tested range is raised to a
 * low-severity recommendation so drift is visible in the backlog.
 */
export function findApiVersion(clean: Record<string, unknown>): Finding[] {
  const version = parseApplicationVersion(clean['info']);
  if (version === null) return [];

  const assessment = assessVersion(version);
  const drifted = assessment.status === 'newer-than-tested' || assessment.status === 'older-than-min';

  return [{
    id: 'API-VERSION',
    section: 'Audit scope',
    severity: drifted ? 'low' : 'info',
    status: drifted ? 'recommendation' : 'ok',
    title: drifted
      ? `Controller version ${version} is outside the tested range`
      : `Controller running UniFi Network ${version}`,
    currentState: assessment.message,
    recommendation: drifted
      ? 'Confirm the audit results against your controller and check for a tool update. The maintainer schema-drift check flags UniFi API changes before they break the audit.'
      : null,
    intentQuestion: null,
    evidence: { version, testedMin: TESTED_MIN, testedMax: TESTED_MAX, status: assessment.status },
    mapsTo: {}, effort: 'quick', impact: 'low',
  }];
}
