import { Configuration, ThreatIntelSource } from './types';
import { createDefaultProviderSettings } from './services/llmProviders';

const CLIENT_PREFERENCES_KEY = 'cerberusClientPreferences';
const DEFAULT_BACKEND_BASE_URL = 'http://localhost:8081';
const LEGACY_BACKEND_BASE_URL = 'http://localhost:8080';

const createDefaultThreatIntelSources = (): ThreatIntelSource[] => [
  {
    id: crypto.randomUUID(),
    name: 'Spamhaus DROP',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    format: 'spamhaus_drop',
    enabled: true,
  },
  {
    id: crypto.randomUUID(),
    name: 'Spamhaus EDROP',
    url: 'https://www.spamhaus.org/drop/edrop.txt',
    format: 'spamhaus_drop',
    enabled: true,
  },
];

export const createId = () => crypto.randomUUID();

const createDefaultConfig = (backendBaseUrl: string): Configuration => ({
  llmProvider: 'lmstudio',
  providerSettings: createDefaultProviderSettings(),
  backendBaseUrl,
  deploymentMode: 'standalone',
  sensorId: 'desktop-lab-01',
  sensorName: 'Windows Lab Sensor',
  hubUrl: '',
  fleetSharedToken: '',
  globalBlockPropagationEnabled: false,
  captureInterface: '',
  captureFilter: 'ip and (tcp or udp)',
  cacheTtlSeconds: 60,
  batchWindowMs: 2000,
  batchMaxSize: 20,
  securePort: 9999,
  monitoringPorts: [22, 80, 443, 8080, 3389],
  detectionThreshold: 0.75,
  autoBlockThreats: false,
  liveRawFeedEnabled: false,
  firewallIntegrationEnabled: false,
  pcapBufferSize: 10,
  payloadMaskingMode: 'raw_local_only',
  threatIntelEnabled: false,
  threatIntelRefreshHours: 24,
  threatIntelAutoBlock: false,
  threatIntelSources: createDefaultThreatIntelSources(),
  blockedIps: [],
  blockedPorts: [],
  exemptPorts: [],
  webhookIntegrations: [],
  customRules: [],
});

export const getInitialConfig = (): Configuration => {
  try {
    const savedPreferences = localStorage.getItem(CLIENT_PREFERENCES_KEY);
    if (savedPreferences) {
      const parsed = JSON.parse(savedPreferences) as { backendBaseUrl?: unknown };
      if (typeof parsed.backendBaseUrl === 'string' && parsed.backendBaseUrl.trim()) {
        const normalizedBackendBaseUrl = parsed.backendBaseUrl.trim() === LEGACY_BACKEND_BASE_URL
          ? DEFAULT_BACKEND_BASE_URL
          : parsed.backendBaseUrl.trim();
        return createDefaultConfig(normalizedBackendBaseUrl);
      }
    }
  } catch (error) {
    console.error('Failed to load client preferences from localStorage', error);
  }

  return createDefaultConfig(DEFAULT_BACKEND_BASE_URL);
};

export const saveClientPreferences = (config: Pick<Configuration, 'backendBaseUrl'>) => {
  try {
    localStorage.setItem(CLIENT_PREFERENCES_KEY, JSON.stringify({
      backendBaseUrl: config.backendBaseUrl.trim() || DEFAULT_BACKEND_BASE_URL,
    }));
  } catch (error) {
    console.error('Failed to save client preferences to localStorage', error);
  }
};
