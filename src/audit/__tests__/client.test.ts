import { describe, it, expect } from 'vitest';
import { UniFiClient } from '../client.js';

describe('UniFiClient', () => {
  it('throws if UNIFI_API_KEY is not set', () => {
    expect(() => UniFiClient.fromEnv({ UNIFI_API_KEY: '', UNIFI_HOST: '192.168.1.1' })).toThrow('UNIFI_API_KEY');
  });
  it('throws if neither host nor cloud set', () => {
    expect(() => UniFiClient.fromEnv({ UNIFI_API_KEY: 'k', UNIFI_HOST: '', UNIFI_USE_CLOUD: '' })).toThrow('UNIFI_HOST');
  });
  it('verifySSL true for cloud mode', () => {
    expect(UniFiClient.fromEnv({ UNIFI_API_KEY: 'k', UNIFI_USE_CLOUD: 'true', UNIFI_HOST: '' }).config.verifySSL).toBe(true);
  });
  it('verifySSL false for local mode', () => {
    expect(UniFiClient.fromEnv({ UNIFI_API_KEY: 'k', UNIFI_HOST: '192.168.1.1', UNIFI_USE_CLOUD: '' }).config.verifySSL).toBe(false);
  });
});
