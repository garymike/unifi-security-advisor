import { Agent, fetch as undiciFetch } from 'undici';

const IS_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

export interface ClientConfig {
  key: string;
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
    const url = path.startsWith('http') ? path : `${this.baseUrl()}${path}`;
    try {
      let resp: { status: number; json(): Promise<unknown> };

      if (IS_TAURI) {
        // Tauri webview context — use plugin-http (proxied through Rust, handles TLS)
        const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
        resp = await tauriFetch(url, {
          headers: { 'X-API-KEY': this.config.key, 'Accept': 'application/json' },
        });
      } else {
        // Node.js CLI context — use undici with TLS bypass for self-signed certs
        const dispatcher = new Agent({ connect: { rejectUnauthorized: this.config.verifySSL } });
        resp = await undiciFetch(url, {
          headers: { 'X-API-KEY': this.config.key, 'Accept': 'application/json' },
          dispatcher,
        });
      }

      let data: unknown;
      try { data = await resp.json(); } catch { data = { nonJsonResponse: true }; }
      return { status: resp.status, data };
    } catch (err) {
      return { status: 0, data: { error: String(err).replace(this.config.key, '<REDACTED>') } };
    }
  }
}
