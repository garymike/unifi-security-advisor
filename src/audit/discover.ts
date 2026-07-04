import { SITE_ENDPOINT_CONCEPTS, specSitePath } from './endpoints.js';

/**
 * Extracts the set of advertised paths from a fetched OpenAPI document. Returns
 * an empty set for anything that isn't a spec with a `paths` object.
 */
export function parseSpecPaths(spec: unknown): Set<string> {
  if (spec === null || typeof spec !== 'object') return new Set();
  const paths = (spec as Record<string, unknown>)['paths'];
  if (paths === null || typeof paths !== 'object') return new Set();
  return new Set(Object.keys(paths as Record<string, unknown>));
}

/**
 * Given the set of paths a console advertises, resolves each endpoint concept to
 * the first of its candidate suffixes that the console actually exposes. Concepts
 * with no advertised candidate are omitted (we won't request them — no 404).
 * Returns `[internalKey, suffix]` pairs.
 */
export function resolveSiteEndpoints(advertised: Set<string>): Array<[string, string]> {
  const resolved: Array<[string, string]> = [];
  for (const [key, concept] of Object.entries(SITE_ENDPOINT_CONCEPTS)) {
    const match = concept.candidates.find(suffix => advertised.has(specSitePath(suffix)));
    if (match) resolved.push([key, match]);
  }
  return resolved;
}
