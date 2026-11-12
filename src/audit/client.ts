// undici is Node.js-only — imported dynamically so Vite doesn't bundle it for the browser
const IS_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

export interface ClientConfig {
  /**
   * The API key, for the Node CLI only. In the desktop app the key never
   * passes through the page: the Rust backend holds it in an open connection
   * (see src/lib/onboarding/keychain.ts) and sends it only to that
   * connection's controller, so leave this unset there.
   */
  key?: string;
  host: string;
  useCloud: boolean;
  verifySSL: boolean;
  profile: string;
}

export interface FetchResult {
  status: number;
  data: unknown;
}

export class UniFiClient {
  readonly config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = config;
  }

  static fromEnv(env: Record<string, string | undefined> = process.env as Record<string, string>): UniFiClient {
    const host = (env['UNIFI_HOST'] ?? '').trim();
    const useCloud = ['1', 'true', 'yes'].includes((env['UNIFI_USE_CLOUD'] ?? '').toLowerCase());

    // Key selection: prefer mode-specific names, fall back to generic UNIFI_API_KEY
    const key = useCloud
      ? (env['UNIFI_SITEMGR_API_KEY'] ?? env['UNIFI_API_KEY'] ?? '').trim()
      : (env['UNIFI_NETWORK_API_KEY'] ?? env['UNIFI_API_KEY'] ?? '').trim();

    if (!key) throw new Error(
      useCloud
        ? 'UNIFI_SITEMGR_API_KEY (or UNIFI_API_KEY) not set'
        : 'UNIFI_NETWORK_API_KEY (or UNIFI_API_KEY) not set'
    );

    if (!host && !useCloud) throw new Error('UNIFI_HOST not set (and UNIFI_USE_CLOUD not enabled)');

    const verifySslEnv = (env['UNIFI_VERIFY_SSL'] ?? '').toLowerCase();
    const verifySSL = verifySslEnv === '1' || verifySslEnv === 'true' ? true
      : verifySslEnv === '0' || verifySslEnv === 'false' ? false
      : useCloud;

    return new UniFiClient({ key, host, useCloud, verifySSL, profile: env['UNIFI_PROFILE'] ?? 'home_office' });
  }

  private baseUrl(): string {
    if (this.config.useCloud) return 'https://api.ui.com';
    const h = this.config.host;
    return h.startsWith('http') ? h : `https://${h}`;
  }

  async get(path: string): Promise<FetchResult> {
    const key = this.config.key ?? '';
    try {
      if (IS_TAURI) {
        // Tauri context: the backend resolves the path against the open
        // connection's controller, refuses any other origin, and adds the key
        // itself. TLS verification is decided there too (on for cloud).
        const { invoke } = await import('@tauri-apps/api/core');
        const result = await invoke<{ status: number; data: unknown }>('unifi_fetch', { path });
        return { status: result.status, data: result.data };
      } else {
        const url = path.startsWith('http') ? path : `${this.baseUrl()}${path}`;
        // Node.js CLI context — dynamically import undici (Node.js-only, not for browsers)
        const { Agent, fetch: undiciFetch } = await import('undici');
        const dispatcher = new Agent({ connect: { rejectUnauthorized: this.config.verifySSL } });
        const resp = await undiciFetch(url, {
          headers: { 'X-API-KEY': key, 'Accept': 'application/json' },
          dispatcher,
        });
        let data: unknown;
        try { data = await resp.json(); } catch { data = { nonJsonResponse: true }; }
        return { status: resp.status, data };
      }
    } catch (err) {
      const msg = String(err);
      return { status: 0, data: { error: key ? msg.replaceAll(key, '<REDACTED>') : msg } };
    }
  }
}
