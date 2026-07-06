// Builds the "mint a key" deep-link. The cloud PORTAL is unifi.ui.com (distinct
// from the api.ui.com API host used for validation). Local opens the Network
// app root — the exact Integrations sub-path varies by Network 8/9/10.
export function keyPortalUrl(mode: 'local' | 'cloud', host?: string): string | null {
  if (mode === 'cloud') return 'https://unifi.ui.com';
  const h = (host ?? '').trim();
  if (!h) return null;
  const base = h.startsWith('http') ? h : `https://${h}`;
  return `${base.replace(/\/+$/, '')}/network/`;
}
