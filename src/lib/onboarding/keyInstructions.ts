export type ConnectMode = 'local' | 'cloud';
export type ConnectTier = 'guided' | 'standard' | 'pro';
export interface InstructionBlock { steps: string[]; note: string }

const REVOKE_NOTE = 'Pick the shortest expiration offered, and revoke the key after this audit.';

const LOCAL: Record<ConnectTier, InstructionBlock> = {
  guided: {
    steps: [
      'Open your UniFi console in a browser and sign in as an admin.',
      'Go to Settings (the gear), then Control Plane, then Integrations.',
      'Give the key a name, choose the shortest expiration, and create it.',
      'Copy the key it shows you — it is only shown once — and paste it below.',
    ],
    note: REVOKE_NOTE,
  },
  standard: {
    steps: [
      'In the UniFi Network application: Settings → Control Plane → Integrations.',
      'Create API Key → name it → set the shortest expiration → Create.',
      'Copy the key (shown once) and paste it below.',
    ],
    note: REVOKE_NOTE,
  },
  pro: {
    steps: [
      'Settings → Control Plane → Integrations → Create API Key.',
      'This mints a Network Integration (local) X-API-KEY, sent as the X-API-KEY header to /proxy/network/integration/v1.',
      'Menu path varies by Network 8/9/10; the key is displayed once — copy it immediately.',
    ],
    note: REVOKE_NOTE,
  },
};

const CLOUD: Record<ConnectTier, InstructionBlock> = {
  guided: {
    steps: [
      'Open unifi.ui.com in a browser and sign in with your Ubiquiti account.',
      'In the left menu, click API.',
      'Click Create API Key, then copy the key it shows — it appears only once.',
      'Paste the key below.',
    ],
    note: REVOKE_NOTE,
  },
  standard: {
    steps: [
      'Sign in at unifi.ui.com → left nav → API.',
      'Create API Key → copy it (shown once).',
      'Paste the key below.',
    ],
    note: REVOKE_NOTE,
  },
  pro: {
    steps: [
      'unifi.ui.com → API → Create API Key.',
      'This is a Site Manager X-API-KEY (cloud), used against https://api.ui.com; one key can span multiple consoles/sites under the account.',
      'Displayed once — copy immediately.',
    ],
    note: REVOKE_NOTE,
  },
};

const TABLE: Record<ConnectMode, Record<ConnectTier, InstructionBlock>> = { local: LOCAL, cloud: CLOUD };

export function getInstructions(mode: ConnectMode, tier: ConnectTier): InstructionBlock {
  return TABLE[mode][tier];
}
