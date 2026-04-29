import type { Finding } from '../audit/types.js';
import type { Tier } from '../db/schema.js';

export function getTieredString(
  finding: Finding,
  field: 'currentState' | 'recommendation' | 'intentQuestion',
  tier: Tier,
): string | null {
  if (tier !== 'standard' && finding.tiers?.[tier]) {
    const override = finding.tiers[tier]![
      field === 'currentState' ? 'currentState'
      : field === 'recommendation' ? 'recommendation'
      : 'intentQuestion'
    ];
    if (override) return override;
  }
  return finding[field === 'currentState' ? 'currentState'
    : field === 'recommendation' ? 'recommendation'
    : 'intentQuestion'] ?? null;
}
