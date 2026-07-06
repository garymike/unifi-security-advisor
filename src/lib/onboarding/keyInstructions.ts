export type ConnectMode = 'local' | 'cloud';
export type ConnectTier = 'guided' | 'standard' | 'pro';
export interface InstructionBlock { steps: string[]; note: string }

const REVOKE_NOTE = 'Pick the shortest expiration offered, and revoke the key after this audit.';
const LOCAL_NOTE =
  'Pick the shortest expiration and revoke the key after this audit. ' +
  'No Integrations section? Sign in as the console Owner (not a limited admin) — ' +
  'or use a cloud key instead: go Back and choose "Through the cloud".';

const LOCAL: Record<ConnectTier, InstructionBlock> = {
  guided: {
    steps: [
      'Open your UniFi console in a browser and sign in with the Owner account.',
      'Open the Integrations section — it has its own button in the console (it is not under Settings).',
      'Create an API key: give it a name, choose the shortest expiration, and create it.',
      'Copy the key it shows you — it is only shown once — and paste it below.',
    ],
    note: LOCAL_NOTE,
  },
  standard: {
    steps: [
      'In your UniFi console, open the Integrations section — a dedicated button, not under Settings → Control Plane.',
      'Create API Key → name it → set the shortest expiration → Create.',
      'Copy the key (shown once) and paste it below.',
    ],
    note: LOCAL_NOTE,
  },
  pro: {
    steps: [
      'Open the console Integrations section (its own top-level area — not Settings → Control Plane → Integrations, which moved in Network 10.x) → Create API Key.',
      'Mints a Network Integration (local) X-API-KEY, sent as the X-API-KEY header to /proxy/network/integration/v1; requires the console Owner account.',
      'Shown once — copy it immediately. If Integrations is missing, use a Site Manager (cloud) key instead.',
    ],
    note: LOCAL_NOTE,
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
