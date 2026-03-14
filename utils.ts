import { Configuration, ThreatIntelSource } from './types';
import { createDefaultProviderSettings } from './services/llmProviders';

const CLIENT_PREFERENCES_KEY = 'cerberusClientPreferences';
const CLIENT_PREFERENCES_VERSION = 2;
const DEFAULT_BACKEND_BASE_URL = 'http://localhost:8081';
const LEGACY_BACKEND_BASE_URL = 'http://localhost:8080';

const normalizeBackendBaseUrl = (backendBaseUrl: string) => backendBaseUrl.trim().replace(/\/+$/, '') || DEFAULT_BACKEND_BASE_URL;

interface ClientPreferences {
  version: number;
  backendBaseUrl: string;
  lastServerInstanceId: string | null;
}

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

const loadClientPreferences = (): ClientPreferences | null => {
  const savedPreferences = localStorage.getItem(CLIENT_PREFERENCES_KEY);
  if (!savedPreferences) {
    return null;
  }

  const parsed = JSON.parse(savedPreferences) as {
    version?: unknown;
    backendBaseUrl?: unknown;
    lastServerInstanceId?: unknown;
  };

  if (typeof parsed.backendBaseUrl !== 'string' || !parsed.backendBaseUrl.trim()) {
    return null;
  }

  const normalizedBackendBaseUrl = normalizeBackendBaseUrl(parsed.backendBaseUrl);
  const migratedBackendBaseUrl = normalizedBackendBaseUrl === LEGACY_BACKEND_BASE_URL
    ? DEFAULT_BACKEND_BASE_URL
    : normalizedBackendBaseUrl;

  return {
    version: typeof parsed.version === 'number' ? parsed.version : 1,
    backendBaseUrl: migratedBackendBaseUrl,
    lastServerInstanceId: typeof parsed.lastServerInstanceId === 'string' && parsed.lastServerInstanceId.trim()
      ? parsed.lastServerInstanceId.trim()
      : null,
  };
};

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
  localLlmTimeoutSeconds: 300,
  payloadMaskingMode: 'raw_local_only',
  sandboxEnabled: true,
  sandboxProvider: 'cerberus_lab',
  sandboxBaseUrl: 'http://localhost:8090',
  sandboxApiKey: '',
  sandboxPollingIntervalMs: 5000,
  sandboxTimeoutSeconds: 300,
  sandboxAutoSubmitSuspicious: false,
  sandboxPrioritizeLlmWorkloads: true,
  sandboxDynamicExecutionEnabled: true,
  sandboxDynamicRuntimeSeconds: 45,
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
    const savedPreferences = loadClientPreferences();
    if (savedPreferences?.backendBaseUrl) {
      return createDefaultConfig(savedPreferences.backendBaseUrl);
    }
  } catch (error) {
    console.error('Failed to load client preferences from localStorage', error);
  }

  return createDefaultConfig(DEFAULT_BACKEND_BASE_URL);
};

export const saveClientPreferences = (config: Pick<Configuration, 'backendBaseUrl'>, options?: { lastServerInstanceId?: string | null }) => {
  const existingPreferences = (() => {
    try {
      return loadClientPreferences();
    } catch {
      return null;
    }
  })();

  try {
    localStorage.setItem(CLIENT_PREFERENCES_KEY, JSON.stringify({
      version: CLIENT_PREFERENCES_VERSION,
      backendBaseUrl: normalizeBackendBaseUrl(config.backendBaseUrl),
      lastServerInstanceId: options?.lastServerInstanceId
        ?? existingPreferences?.lastServerInstanceId
        ?? null,
    }));
  } catch (error) {
    console.error('Failed to save client preferences to localStorage', error);
  }
};

export const getLastSeenServerInstanceId = (): string | null => {
  try {
    return loadClientPreferences()?.lastServerInstanceId ?? null;
  } catch (error) {
    console.error('Failed to load server instance id from localStorage', error);
    return null;
  }
};

export const markSeenServerInstance = (config: Pick<Configuration, 'backendBaseUrl'>, serverInstanceId: string) => {
  saveClientPreferences(config, { lastServerInstanceId: serverInstanceId });
};
