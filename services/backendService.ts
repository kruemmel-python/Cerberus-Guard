import {
  BootstrapPayload,
  CaptureInterface,
  CaptureStatusPayload,
  Configuration,
  LogEntry,
  MetricSnapshot,
  PcapArtifact,
  SandboxAnalysisSummary,
  SensorSummary,
  ServerConfiguration,
  ThreatHuntingResponse,
  ThreatIntelStatus,
  TrafficLogEntry,
  TrafficMetricPoint,
} from '../types';

const normalizeBaseUrl = (baseUrl: string) => {
  const trimmed = baseUrl.trim();
  return trimmed.replace(/\/+$/, '') || 'http://localhost:8081';
};

const toClientConfiguration = (config: ServerConfiguration, baseUrl: string): Configuration => ({
  ...config,
  backendBaseUrl: normalizeBaseUrl(baseUrl),
});

const toServerConfiguration = (config: Configuration): ServerConfiguration => {
  const { backendBaseUrl: _backendBaseUrl, ...serverConfig } = config;
  return {
    ...serverConfig,
    providerSettings: Object.fromEntries(
      Object.entries(serverConfig.providerSettings).map(([providerId, settings]) => [
        providerId,
        {
          ...settings,
          apiKey: settings.apiKey ?? '',
        },
      ])
    ) as ServerConfiguration['providerSettings'],
  };
};

const fetchJson = async <T>(url: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(url, init);
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};

  if (!response.ok) {
    throw new Error((data && typeof data.error === 'string' && data.error) || `Request failed with status ${response.status}`);
  }

  return data as T;
};

export const buildTrafficWebSocketUrl = (baseUrl: string) => {
  const normalizedBaseUrl = normalizeBaseUrl(baseUrl);
  const parsedUrl = new URL(normalizedBaseUrl);
  parsedUrl.protocol = parsedUrl.protocol === 'https:' ? 'wss:' : 'ws:';
  parsedUrl.pathname = '/traffic';
  parsedUrl.search = '';
  return parsedUrl.toString();
};

const withSensorQuery = (sensorId?: string | null) => (sensorId ? `?sensorId=${encodeURIComponent(sensorId)}` : '');

export const getBackendHealth = async (baseUrl: string) =>
  fetchJson<{ ok: boolean; capture: CaptureStatusPayload }>(`${normalizeBaseUrl(baseUrl)}/api/health`);

export const listCaptureInterfaces = async (baseUrl: string) =>
  fetchJson<{ interfaces: CaptureInterface[] }>(`${normalizeBaseUrl(baseUrl)}/api/interfaces`);

export const getBootstrap = async (baseUrl: string, sensorId?: string | null) => {
  const payload = await fetchJson<BootstrapPayload>(`${normalizeBaseUrl(baseUrl)}/api/bootstrap${withSensorQuery(sensorId)}`);
  return {
    ...payload,
    config: toClientConfiguration(payload.config, baseUrl),
  };
};

export const getConfig = async (baseUrl: string) => {
  const response = await fetchJson<{ config: ServerConfiguration }>(`${normalizeBaseUrl(baseUrl)}/api/config`);
  return toClientConfiguration(response.config, baseUrl);
};

export const updateConfig = async (config: Configuration) => {
  const baseUrl = normalizeBaseUrl(config.backendBaseUrl);
  const response = await fetchJson<{ ok: boolean; config: ServerConfiguration }>(`${baseUrl}/api/config`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(toServerConfiguration(config)),
  });

  return toClientConfiguration(response.config, baseUrl);
};

export const getCaptureStatus = async (baseUrl: string) =>
  fetchJson<CaptureStatusPayload>(`${normalizeBaseUrl(baseUrl)}/api/capture/status`);

export const startCapture = async (config: Configuration) =>
  fetchJson<{ ok: boolean; status: CaptureStatusPayload }>(`${normalizeBaseUrl(config.backendBaseUrl)}/api/capture/start`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      deviceName: config.captureInterface,
      filter: config.captureFilter,
    }),
  });

export const stopCapture = async (baseUrl: string) =>
  fetchJson<{ ok: boolean; status: CaptureStatusPayload }>(`${normalizeBaseUrl(baseUrl)}/api/capture/stop`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });

export const startReplay = async (baseUrl: string, file: File, speedMultiplier: number) => {
  const formData = new FormData();
  formData.append('pcap', file);
  formData.append('speedMultiplier', String(speedMultiplier));

  return fetchJson<{ ok: boolean; message: string }>(`${normalizeBaseUrl(baseUrl)}/api/capture/replay`, {
    method: 'POST',
    body: formData,
  });
};

export const getLogs = async (baseUrl: string, limit = 500, sensorId?: string | null) =>
  fetchJson<{ logs: LogEntry[] }>(
    `${normalizeBaseUrl(baseUrl)}/api/logs?limit=${limit}${sensorId ? `&sensorId=${encodeURIComponent(sensorId)}` : ''}`
  );

export const getTraffic = async (baseUrl: string, limit = 100, sensorId?: string | null) =>
  fetchJson<{ traffic: TrafficLogEntry[] }>(
    `${normalizeBaseUrl(baseUrl)}/api/traffic?limit=${limit}${sensorId ? `&sensorId=${encodeURIComponent(sensorId)}` : ''}`
  );

export const getMetrics = async (baseUrl: string, hours = 24, bucketMinutes = 15, sensorId?: string | null) =>
  fetchJson<{ snapshot: MetricSnapshot; series: TrafficMetricPoint[] }>(
    `${normalizeBaseUrl(baseUrl)}/api/metrics?hours=${hours}&bucketMinutes=${bucketMinutes}${sensorId ? `&sensorId=${encodeURIComponent(sensorId)}` : ''}`
  );

export const getPcapArtifacts = async (baseUrl: string, limit = 50, sensorId?: string | null) =>
  fetchJson<{ artifacts: PcapArtifact[] }>(
    `${normalizeBaseUrl(baseUrl)}/api/pcap-artifacts?limit=${limit}${sensorId ? `&sensorId=${encodeURIComponent(sensorId)}` : ''}`
  );

export const getSandboxAnalyses = async (baseUrl: string, limit = 25, sensorId?: string | null) =>
  fetchJson<{ analyses: SandboxAnalysisSummary[] }>(
    `${normalizeBaseUrl(baseUrl)}/api/sandbox/analyses?limit=${limit}${sensorId ? `&sensorId=${encodeURIComponent(sensorId)}` : ''}`
  );

export const listSensors = async (baseUrl: string) =>
  fetchJson<{ sensors: SensorSummary[] }>(`${normalizeBaseUrl(baseUrl)}/api/fleet/sensors`);

export const getThreatIntelStatus = async (baseUrl: string) =>
  fetchJson<{ status: ThreatIntelStatus }>(`${normalizeBaseUrl(baseUrl)}/api/threat-intel/status`);

export const refreshThreatIntel = async (baseUrl: string) =>
  fetchJson<{ ok: boolean; status: ThreatIntelStatus }>(`${normalizeBaseUrl(baseUrl)}/api/threat-intel/refresh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  });

export const runThreatHunt = async (baseUrl: string, question: string, sensorId?: string | null) =>
  fetchJson<{ ok: boolean; result: ThreatHuntingResponse }>(`${normalizeBaseUrl(baseUrl)}/api/forensics/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      question,
      sensorId: sensorId || null,
    }),
  });

export const revealLocalPath = async (baseUrl: string, targetPath: string) =>
  fetchJson<{ ok: boolean; revealedPath: string }>(`${normalizeBaseUrl(baseUrl)}/api/local-process/open-path`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      path: targetPath,
    }),
  });

export const analyzeProcessFileInSandbox = async (
  baseUrl: string,
  targetPath: string,
  options?: { processName?: string | null; trafficEventId?: string | null }
) =>
  fetchJson<{ ok: boolean; analysis: SandboxAnalysisSummary; error?: string; }>(`${normalizeBaseUrl(baseUrl)}/api/sandbox/analyze-process`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      path: targetPath,
      processName: options?.processName || null,
      trafficEventId: options?.trafficEventId || null,
    }),
  });

export const getArtifactDownloadUrl = (baseUrl: string, artifactId: string) =>
  `${normalizeBaseUrl(baseUrl)}/api/pcap-artifacts/${encodeURIComponent(artifactId)}/download`;
