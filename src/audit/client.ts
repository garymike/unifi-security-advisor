import { Agent, fetch as undiciFetch } from 'undici';

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
    const key = (env['UNIFI_API_KEY'] ?? '').trim();
    if (!key) throw new Error('UNIFI_API_KEY environment variable not set');

    const host = (env['UNIFI_HOST'] ?? '').trim();
    const useCloud = ['1', 'true', 'yes'].includes((env['UNIFI_USE_CLOUD'] ?? '').toLowerCase());
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
      // Use undici's fetch with a custom Agent so rejectUnauthorized works for
      // local controllers that use self-signed certificates.
      const dispatcher = new Agent({ connect: { rejectUnauthorized: this.config.verifySSL } });
      const resp = await undiciFetch(url, {
        headers: { 'X-API-KEY': this.config.key, 'Accept': 'application/json' },
        dispatcher,
      });
      let data: unknown;
      try { data = await resp.json(); } catch { data = { nonJsonResponse: true }; }
      return { status: resp.status, data };
    } catch (err) {
      return { status: 0, data: { error: String(err).replace(this.config.key, '<REDACTED>') } };
    }
  }
}
