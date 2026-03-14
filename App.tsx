import React, { startTransition, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './components/Dashboard';
import { Settings } from './components/Settings';
import { Logs } from './components/Logs';
import { RuleBuilder } from './components/RuleBuilder';
import { FleetManagement } from './components/FleetManagement';
import { ThreatHunter } from './components/ThreatHunter';
import {
  buildTrafficWebSocketUrl,
  analyzeProcessFileInSandbox,
  retrySandboxAnalystReview,
  analyzeUploadedFileInSandbox,
  getSandboxLlmDebug,
  getBootstrap,
  getBackendHealth,
  listCaptureInterfaces,
  revealLocalPath,
  startCapture,
  startReplay,
  stopCapture,
  updateConfig,
  getArtifactDownloadUrl,
  getSandboxReportDownloadUrl,
  refreshThreatIntel,
  normalizeBaseUrl,
} from './services/backendService';
import { getProviderDefinition, getSelectedProviderSettings } from './services/llmProviders';
import {
  BackendWsMessage,
  CaptureInterface,
  CaptureStatusPayload,
  Configuration,
  FleetStatusPayload,
  LogEntry,
  LogLevel,
  MetricSnapshot,
  MonitoringStatus,
  Packet,
  PcapArtifact,
  SandboxAnalysisSummary,
  SandboxLlmDebugPayload,
  ReplayStatusPayload,
  SensorSummary,
  ThreatIntelStatus,
  TrafficLogEntry,
  TrafficMetricPoint,
} from './types';
import { useLocalization } from './hooks/useLocalization';
import { createId, getInitialConfig, getLastSeenServerInstanceId, markSeenServerInstance, saveClientPreferences } from './utils';

const MAX_LOG_ENTRIES = 500;
const MAX_FEED_ENTRIES = 100;
const MAX_ARTIFACT_ENTRIES = 50;
const MAX_RAW_FEED_ENTRIES = 25;
const MAX_SANDBOX_ANALYSES = 25;
const CONFIG_SYNC_DELAY_MS = 700;
const BACKEND_SWITCH_DELAY_MS = 500;
const SOCKET_RECONNECT_DELAY_MS = 3000;
const DISCONNECTED_REFRESH_INTERVAL_MS = 5000;

type NavigationTab = 'Dashboard' | 'Rules' | 'Settings' | 'Logs' | 'Fleet' | 'ThreatHunt';
type ConfigSyncState = 'idle' | 'saving' | 'saved' | 'error';

const createInitialMetricSnapshot = (): MetricSnapshot => ({
  packetsProcessed: 0,
  threatsDetected: 0,
  blockedDecisions: 0,
  lastUpdatedAt: new Date(0).toISOString(),
});

const createEmptyReplayStatus = (): ReplayStatusPayload => ({
  state: 'idle',
  fileName: null,
  processedPackets: 0,
  totalPackets: 0,
  startedAt: null,
  completedAt: null,
  message: null,
});

const createEmptyFleetStatus = (): FleetStatusPayload => ({
  deploymentMode: 'standalone',
  sensorId: 'desktop-lab-01',
  sensorName: 'Windows Lab Sensor',
  connectedToHub: false,
  connectedSensors: 0,
  hubUrl: null,
  lastSyncAt: null,
  lastError: null,
});

const createEmptyThreatIntelStatus = (): ThreatIntelStatus => ({
  enabled: false,
  loadedIndicators: 0,
  sourceCount: 0,
  lastRefreshAt: null,
  lastError: null,
  refreshing: false,
});

const createInitialMonitoringStatus = (): MonitoringStatus => ({
  backendReachable: false,
  websocketConnected: false,
  captureRunning: false,
  activeDevice: null,
  activeFilter: '',
  lastStartedAt: null,
  lastError: null,
  replayStatus: createEmptyReplayStatus(),
  fleetStatus: createEmptyFleetStatus(),
  threatIntelStatus: createEmptyThreatIntelStatus(),
});

const mergeById = <T extends { id: string },>(items: T[], incomingItem: T, limit: number) =>
  [incomingItem, ...items.filter(item => item.id !== incomingItem.id)].slice(0, limit);

const serializeServerConfig = (config: Configuration) => {
  const { backendBaseUrl: _backendBaseUrl, ...serverConfig } = config;
  return JSON.stringify(serverConfig);
};

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavigationTab>('Dashboard');
  const [config, setConfig] = useState<Configuration>(getInitialConfig);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [liveTrafficFeed, setLiveTrafficFeed] = useState<TrafficLogEntry[]>([]);
  const [rawPacketFeed, setRawPacketFeed] = useState<Packet[]>([]);
  const [trafficMetrics, setTrafficMetrics] = useState<TrafficMetricPoint[]>([]);
  const [artifacts, setArtifacts] = useState<PcapArtifact[]>([]);
  const [sandboxAnalyses, setSandboxAnalyses] = useState<SandboxAnalysisSummary[]>([]);
  const [availableInterfaces, setAvailableInterfaces] = useState<CaptureInterface[]>([]);
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus>(createInitialMonitoringStatus);
  const [metricsSnapshot, setMetricsSnapshot] = useState<MetricSnapshot>(createInitialMetricSnapshot);
  const [captureActionPending, setCaptureActionPending] = useState(false);
  const [replayActionPending, setReplayActionPending] = useState(false);
  const [configSyncState, setConfigSyncState] = useState<ConfigSyncState>('idle');
  const [applySettingsPending, setApplySettingsPending] = useState(false);
  const [sensors, setSensors] = useState<SensorSummary[]>([]);
  const [selectedSensorId, setSelectedSensorId] = useState<string | null>(null);
  const [threatIntelRefreshPending, setThreatIntelRefreshPending] = useState(false);
  const [backendAppliedProviderLabel, setBackendAppliedProviderLabel] = useState('LM Studio / local-model');
  const { t } = useLocalization();

  const websocketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const configSyncTimerRef = useRef<number | null>(null);
  const configSyncStateTimerRef = useRef<number | null>(null);
  const bootstrapRequestIdRef = useRef(0);
  const activeBaseUrlRef = useRef(normalizeBaseUrl(config.backendBaseUrl));
  const configRef = useRef(config);
  const backendContextReadyRef = useRef(false);
  const isDisposedRef = useRef(false);
  const lastServerConfigRef = useRef(serializeServerConfig(config));
  const selectedSensorIdRef = useRef<string | null>(null);
  const lastSeenServerInstanceIdRef = useRef<string | null>(getLastSeenServerInstanceId());
  const previousLlmProviderRef = useRef(config.llmProvider);

  useEffect(() => {
    configRef.current = config;
  }, [config]);

  useEffect(() => {
    selectedSensorIdRef.current = selectedSensorId;
  }, [selectedSensorId]);

  useEffect(() => {
    previousLlmProviderRef.current = config.llmProvider;
  }, []);

  const appendClientLog = useCallback((message: string, level: LogLevel, details?: Record<string, unknown>) => {
    const entry: LogEntry = {
      id: createId(),
      timestamp: new Date().toISOString(),
      level,
      message,
      details,
    };

    startTransition(() => {
      setLogs(previousLogs => mergeById(previousLogs, entry, MAX_LOG_ENTRIES));
    });
  }, []);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const clearConfigSyncTimers = useCallback(() => {
    if (configSyncTimerRef.current !== null) {
      window.clearTimeout(configSyncTimerRef.current);
      configSyncTimerRef.current = null;
    }

    if (configSyncStateTimerRef.current !== null) {
      window.clearTimeout(configSyncStateTimerRef.current);
      configSyncStateTimerRef.current = null;
    }
  }, []);

  const resetFrontendState = useCallback(() => {
    backendContextReadyRef.current = false;
    selectedSensorIdRef.current = null;

    startTransition(() => {
      setLogs([]);
      setLiveTrafficFeed([]);
      setRawPacketFeed([]);
      setTrafficMetrics([]);
      setArtifacts([]);
      setSandboxAnalyses([]);
      setAvailableInterfaces([]);
      setSensors([]);
      setSelectedSensorId(null);
      setMetricsSnapshot(createInitialMetricSnapshot());
      setMonitoringStatus(createInitialMonitoringStatus());
      setCaptureActionPending(false);
      setReplayActionPending(false);
      setThreatIntelRefreshPending(false);
      setConfigSyncState('idle');
    });
  }, []);

  const closeTrafficSocket = useCallback(() => {
    clearReconnectTimer();
    if (websocketRef.current) {
      websocketRef.current.onclose = null;
      websocketRef.current.close();
      websocketRef.current = null;
    }
  }, [clearReconnectTimer]);

  const applyCaptureStatus = useCallback((status: CaptureStatusPayload) => {
    setMonitoringStatus(previousStatus => ({
      ...previousStatus,
      backendReachable: true,
      captureRunning: status.running,
      activeDevice: status.activeDevice,
      activeFilter: status.activeFilter,
      lastStartedAt: status.startedAt,
      lastError: null,
    }));
  }, []);

  const markConfigSyncSaved = useCallback(() => {
    setConfigSyncState('saved');
    if (configSyncStateTimerRef.current !== null) {
      window.clearTimeout(configSyncStateTimerRef.current);
    }
    configSyncStateTimerRef.current = window.setTimeout(() => {
      setConfigSyncState('idle');
      configSyncStateTimerRef.current = null;
    }, 1500);
  }, []);

  const hydrateFromBackend = useCallback(async (baseUrl: string, options?: { preserveRawFeed?: boolean; sensorId?: string | null }) => {
    const requestId = ++bootstrapRequestIdRef.current;

    try {
      const payload = await getBootstrap(baseUrl, options?.sensorId ?? selectedSensorIdRef.current);
      if (
        isDisposedRef.current
        || requestId !== bootstrapRequestIdRef.current
        || normalizeBaseUrl(payload.config.backendBaseUrl) !== normalizeBaseUrl(activeBaseUrlRef.current)
      ) {
        return;
      }

      const normalizedBaseUrl = normalizeBaseUrl(baseUrl);
      const instanceChanged = lastSeenServerInstanceIdRef.current !== null
        && lastSeenServerInstanceIdRef.current !== payload.serverInstanceId;
      const requestedSensorId = options?.sensorId ?? selectedSensorIdRef.current;
      const nextSelectedSensorId = payload.sensors.some(sensor => sensor.id === requestedSensorId)
        ? requestedSensorId
        : null;
      const payloadProvider = getProviderDefinition(payload.config.llmProvider);
      const payloadProviderSettings = getSelectedProviderSettings(payload.config);

      lastSeenServerInstanceIdRef.current = payload.serverInstanceId;
      markSeenServerInstance({ backendBaseUrl: normalizedBaseUrl }, payload.serverInstanceId);

      backendContextReadyRef.current = true;
      lastServerConfigRef.current = serializeServerConfig(payload.config);
      setReplayActionPending(payload.replayStatus.state === 'running');

      startTransition(() => {
        if (instanceChanged) {
          setLogs([]);
          setLiveTrafficFeed([]);
          setRawPacketFeed([]);
          setTrafficMetrics([]);
          setArtifacts([]);
          setSandboxAnalyses([]);
          setSensors([]);
          setMetricsSnapshot(createInitialMetricSnapshot());
          setMonitoringStatus(createInitialMonitoringStatus());
        }
        setConfig(payload.config);
        setBackendAppliedProviderLabel(`${payloadProvider.label} / ${payloadProviderSettings.model || payloadProvider.defaultModel}`);
        setAvailableInterfaces(payload.interfaces);
        setLogs(payload.logs.slice(0, MAX_LOG_ENTRIES));
        setLiveTrafficFeed(payload.traffic.slice(0, MAX_FEED_ENTRIES));
        if (!options?.preserveRawFeed) {
          setRawPacketFeed([]);
        }
        setTrafficMetrics(payload.metricSeries);
        setArtifacts(payload.artifacts.slice(0, MAX_ARTIFACT_ENTRIES));
        setSandboxAnalyses(payload.sandboxAnalyses.slice(0, MAX_SANDBOX_ANALYSES));
        setMetricsSnapshot(payload.metrics);
        setSensors(payload.sensors);
        setSelectedSensorId(nextSelectedSensorId);
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          backendReachable: true,
          captureRunning: payload.captureStatus.running,
          activeDevice: payload.captureStatus.activeDevice,
          activeFilter: payload.captureStatus.activeFilter,
          lastStartedAt: payload.captureStatus.startedAt,
          lastError: null,
          replayStatus: payload.replayStatus,
          fleetStatus: payload.fleetStatus,
          threatIntelStatus: payload.threatIntelStatus,
        }));
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: false,
        lastError: message,
      }));
      appendClientLog(t('logBootstrapFailed'), LogLevel.ERROR, { error: message, baseUrl });
    }
  }, [appendClientLog, t]);

  const handleSocketMessage = useCallback((message: BackendWsMessage) => {
    const activeSensorFilter = selectedSensorIdRef.current;

    switch (message.type) {
      case 'capture-status':
        applyCaptureStatus(message.payload);
        setCaptureActionPending(false);
        return;
      case 'capture-error':
        setCaptureActionPending(false);
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          backendReachable: true,
          lastError: message.payload.message,
        }));
        appendClientLog(t('logCaptureError'), LogLevel.ERROR, { error: message.payload.message });
        return;
      case 'metrics-update':
        if (!activeSensorFilter) {
          setMetricsSnapshot(message.payload);
        }
        return;
      case 'traffic-event':
        if (!activeSensorFilter || message.payload.sensorId === activeSensorFilter) {
          startTransition(() => {
            setLiveTrafficFeed(previousFeed => mergeById(previousFeed, message.payload, MAX_FEED_ENTRIES));
          });
        }
        return;
      case 'threat-detected':
        return;
      case 'log-entry':
        if (!activeSensorFilter || message.payload.sensorId === activeSensorFilter) {
          startTransition(() => {
            setLogs(previousLogs => mergeById(previousLogs, message.payload, MAX_LOG_ENTRIES));
          });
        }
        return;
      case 'raw-packet':
        if (!activeSensorFilter || message.payload.sensorId === activeSensorFilter) {
          startTransition(() => {
            setRawPacketFeed(previousFeed => mergeById(previousFeed, message.payload, MAX_RAW_FEED_ENTRIES));
          });
        }
        return;
      case 'replay-status':
        setReplayActionPending(message.payload.state === 'running');
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          replayStatus: message.payload,
        }));
        return;
      case 'pcap-artifact':
        if (!activeSensorFilter || message.payload.sensorId === activeSensorFilter) {
          startTransition(() => {
            setArtifacts(previousArtifacts => mergeById(previousArtifacts, message.payload, MAX_ARTIFACT_ENTRIES));
          });
        }
        return;
      case 'sandbox-analysis':
        if (!activeSensorFilter || message.payload.sensorId === activeSensorFilter) {
          startTransition(() => {
            setSandboxAnalyses(previousAnalyses => mergeById(previousAnalyses, message.payload, MAX_SANDBOX_ANALYSES));
          });
        }
        return;
      case 'fleet-status':
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          fleetStatus: message.payload,
        }));
        return;
      case 'sensor-update':
        startTransition(() => {
          setSensors(previousSensors => mergeById(previousSensors, message.payload, 200));
        });
        return;
      case 'threat-intel-status':
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          threatIntelStatus: message.payload,
        }));
        setThreatIntelRefreshPending(message.payload.refreshing);
        return;
      default:
        return;
    }
  }, [appendClientLog, applyCaptureStatus, t]);

  const connectTrafficSocket = useCallback((baseUrl: string, refreshOnOpen = false) => {
    const normalizedBaseUrl = baseUrl.trim() || 'http://localhost:8081';
    let socketUrl: string;

    try {
      socketUrl = buildTrafficWebSocketUrl(normalizedBaseUrl);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: false,
        websocketConnected: false,
        lastError: message,
      }));
      appendClientLog(t('logWebSocketError'), LogLevel.ERROR, { error: message, baseUrl: normalizedBaseUrl });
      return;
    }

    closeTrafficSocket();

    const socket = new WebSocket(socketUrl);
    websocketRef.current = socket;

    socket.onopen = () => {
      clearReconnectTimer();
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: true,
        websocketConnected: true,
        lastError: null,
      }));

      if (refreshOnOpen) {
        void hydrateFromBackend(normalizedBaseUrl, { preserveRawFeed: true, sensorId: selectedSensorIdRef.current });
      }
    };

    socket.onmessage = event => {
      try {
        const message = JSON.parse(event.data) as BackendWsMessage;
        handleSocketMessage(message);
      } catch (error) {
        appendClientLog(t('logPacketDecodeFailed'), LogLevel.ERROR, {
          error: error instanceof Error ? error.message : t('unknownError'),
        });
      }
    };

    socket.onerror = () => {
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        websocketConnected: false,
        lastError: t('logWebSocketError'),
      }));
    };

    socket.onclose = () => {
      if (websocketRef.current === socket) {
        websocketRef.current = null;
      }

      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        websocketConnected: false,
      }));

      if (isDisposedRef.current || activeBaseUrlRef.current !== normalizedBaseUrl || reconnectTimerRef.current !== null) {
        return;
      }

      reconnectTimerRef.current = window.setTimeout(() => {
        reconnectTimerRef.current = null;
        if (!isDisposedRef.current && activeBaseUrlRef.current === normalizedBaseUrl && !websocketRef.current) {
          connectTrafficSocket(normalizedBaseUrl, true);
        }
      }, SOCKET_RECONNECT_DELAY_MS);
    };
  }, [appendClientLog, clearReconnectTimer, closeTrafficSocket, handleSocketMessage, hydrateFromBackend, t]);

  const refreshInterfaces = useCallback(async (shouldReportErrors = false) => {
    try {
      const response = await listCaptureInterfaces(configRef.current.backendBaseUrl);
      setAvailableInterfaces(response.interfaces);
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: true,
        lastError: null,
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: false,
        lastError: message,
      }));

      if (shouldReportErrors) {
        appendClientLog(t('logInterfacesRefreshFailed'), LogLevel.ERROR, { error: message });
      }
    }
  }, [appendClientLog, t]);

  const syncConfigNow = useCallback(async () => {
    if (!backendContextReadyRef.current) {
      return configRef.current;
    }

    const pendingConfig = configRef.current;
    const serializedConfig = serializeServerConfig(pendingConfig);
    if (serializedConfig === lastServerConfigRef.current) {
      return pendingConfig;
    }

    clearConfigSyncTimers();
    setConfigSyncState('saving');

    const nextConfig = await updateConfig(pendingConfig);
    const appliedProvider = getProviderDefinition(nextConfig.llmProvider);
    const appliedProviderSettings = getSelectedProviderSettings(nextConfig);
    backendContextReadyRef.current = true;
    lastServerConfigRef.current = serializeServerConfig(nextConfig);
    startTransition(() => {
      setConfig(nextConfig);
      setBackendAppliedProviderLabel(`${appliedProvider.label} / ${appliedProviderSettings.model || appliedProvider.defaultModel}`);
    });
    markConfigSyncSaved();
    return nextConfig;
  }, [clearConfigSyncTimers, markConfigSyncSaved]);

  const applySettingsNow = useCallback(async () => {
    setApplySettingsPending(true);

    try {
      const expectedProvider = configRef.current.llmProvider;
      const syncedConfig = await syncConfigNow();
      if (syncedConfig.llmProvider !== expectedProvider) {
        throw new Error(`Backend kept provider "${syncedConfig.llmProvider}" instead of "${expectedProvider}".`);
      }

      await hydrateFromBackend(syncedConfig.backendBaseUrl, {
        preserveRawFeed: true,
        sensorId: selectedSensorIdRef.current,
      });

      window.location.reload();
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setConfigSyncState('error');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        lastError: message,
      }));
      appendClientLog(t('logConfigSyncFailed'), LogLevel.ERROR, {
        error: message,
        scope: 'applySettingsNow',
      });
    } finally {
      setApplySettingsPending(false);
    }
  }, [appendClientLog, hydrateFromBackend, syncConfigNow, t]);

  const startMonitoring = useCallback(async () => {
    setCaptureActionPending(true);

    try {
      const syncedConfig = await syncConfigNow();
      const response = await startCapture(syncedConfig);
      applyCaptureStatus(response.status);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: false,
        lastError: message,
      }));
      appendClientLog(t('logMonitoringStartFailed'), LogLevel.ERROR, { error: message });
    } finally {
      setCaptureActionPending(false);
    }
  }, [appendClientLog, applyCaptureStatus, syncConfigNow, t]);

  const stopMonitoringGracefully = useCallback(async () => {
    setCaptureActionPending(true);

    try {
      const response = await stopCapture(configRef.current.backendBaseUrl);
      applyCaptureStatus(response.status);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        lastError: message,
      }));
      appendClientLog(t('logMonitoringStopFailed'), LogLevel.ERROR, { error: message });
    } finally {
      setCaptureActionPending(false);
    }
  }, [appendClientLog, applyCaptureStatus, t]);

  const startReplayCapture = useCallback(async (file: File, speedMultiplier: number) => {
    setReplayActionPending(true);

    try {
      await startReplay(configRef.current.backendBaseUrl, file, speedMultiplier);
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        backendReachable: true,
        lastError: null,
        replayStatus: {
          ...previousStatus.replayStatus,
          state: 'running',
          fileName: file.name,
          processedPackets: 0,
          totalPackets: previousStatus.replayStatus.totalPackets,
          startedAt: new Date().toISOString(),
          completedAt: null,
          message: null,
        },
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        lastError: message,
      }));
      appendClientLog(t('logReplayStartFailed'), LogLevel.ERROR, { error: message, fileName: file.name });
      setReplayActionPending(false);
    }
  }, [appendClientLog, t]);

  const triggerThreatIntelRefresh = useCallback(async () => {
    setThreatIntelRefreshPending(true);
    try {
      const syncedConfig = await syncConfigNow();
      const response = await refreshThreatIntel(syncedConfig.backendBaseUrl);
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        threatIntelStatus: response.status,
        lastError: null,
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('threatIntelRefreshFailed'), LogLevel.ERROR, { error: message });
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        lastError: message,
      }));
    } finally {
      setThreatIntelRefreshPending(false);
    }
  }, [appendClientLog, syncConfigNow, t]);

  const revealProcessPath = useCallback(async (targetPath: string) => {
    try {
      await revealLocalPath(configRef.current.backendBaseUrl, targetPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('processActionFailed'), LogLevel.ERROR, { error: message, targetPath });
      throw error;
    }
  }, [appendClientLog, t]);

  const analyzeProcessInSandbox = useCallback(async (
    targetPath: string,
    options?: { processName?: string | null; trafficEventId?: string | null }
  ) => {
    try {
      const syncedConfig = await syncConfigNow();
      const response = await analyzeProcessFileInSandbox(syncedConfig.backendBaseUrl, targetPath, options);
      startTransition(() => {
        setSandboxAnalyses(previousAnalyses => mergeById(previousAnalyses, response.analysis, MAX_SANDBOX_ANALYSES));
      });
      return response.analysis;
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('sandboxAnalyzeFailed'), LogLevel.ERROR, {
        error: message,
        targetPath,
        trafficEventId: options?.trafficEventId || null,
      });
      throw error;
    }
  }, [appendClientLog, syncConfigNow, t]);

  const analyzeUploadedFileInSandboxViaUi = useCallback(async (files: File[]) => {
    try {
      const syncedConfig = await syncConfigNow();
      const response = await analyzeUploadedFileInSandbox(syncedConfig.backendBaseUrl, files);
      startTransition(() => {
        setSandboxAnalyses(previousAnalyses => mergeById(previousAnalyses, response.analysis, MAX_SANDBOX_ANALYSES));
      });
      return response.analysis;
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('sandboxUploadFailed'), LogLevel.ERROR, {
        error: message,
        fileName: files[0]?.name || null,
        attachmentCount: Math.max(0, files.length - 1),
      });
      throw error;
    }
  }, [appendClientLog, syncConfigNow, t]);

  const loadSandboxLlmDebug = useCallback(async (analysisId: string): Promise<SandboxLlmDebugPayload> => {
    try {
      const response = await getSandboxLlmDebug(configRef.current.backendBaseUrl, analysisId);
      return response.debug;
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('sandboxDebugLoadFailed'), LogLevel.ERROR, {
        error: message,
        analysisId,
      });
      throw error;
    }
  }, [appendClientLog, t]);

  const retrySandboxAnalystReviewViaUi = useCallback(async (analysisId: string) => {
    try {
      const syncedConfig = await syncConfigNow();
      const response = await retrySandboxAnalystReview(syncedConfig.backendBaseUrl, analysisId);
      startTransition(() => {
        setSandboxAnalyses(previousAnalyses => mergeById(previousAnalyses, response.analysis, MAX_SANDBOX_ANALYSES));
      });
      return response.analysis;
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('sandboxRetryReviewFailed'), LogLevel.ERROR, {
        error: message,
        analysisId,
      });
      throw error;
    }
  }, [appendClientLog, syncConfigNow, t]);

  useEffect(() => {
    const normalizedBaseUrl = normalizeBaseUrl(config.backendBaseUrl);
    activeBaseUrlRef.current = normalizedBaseUrl;
    saveClientPreferences({ backendBaseUrl: activeBaseUrlRef.current });

    closeTrafficSocket();
    resetFrontendState();

    const timeoutId = window.setTimeout(() => {
      void hydrateFromBackend(normalizedBaseUrl, { sensorId: selectedSensorIdRef.current });
      connectTrafficSocket(normalizedBaseUrl, true);
    }, BACKEND_SWITCH_DELAY_MS);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [config.backendBaseUrl, closeTrafficSocket, connectTrafficSocket, hydrateFromBackend, resetFrontendState]);

  useEffect(() => {
    if (!backendContextReadyRef.current) {
      return;
    }

    const serializedConfig = serializeServerConfig(config);
    if (serializedConfig === lastServerConfigRef.current) {
      return;
    }

    clearConfigSyncTimers();
    setConfigSyncState('saving');

    configSyncTimerRef.current = window.setTimeout(() => {
      void updateConfig(configRef.current).then(nextConfig => {
        backendContextReadyRef.current = true;
        lastServerConfigRef.current = serializeServerConfig(nextConfig);
        startTransition(() => {
          setConfig(nextConfig);
        });
        markConfigSyncSaved();
      }).catch(error => {
        const message = error instanceof Error ? error.message : t('unknownError');
        setConfigSyncState('error');
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          lastError: message,
        }));
        appendClientLog(t('logConfigSyncFailed'), LogLevel.ERROR, { error: message });
      }).finally(() => {
        configSyncTimerRef.current = null;
      });
    }, CONFIG_SYNC_DELAY_MS);

    return () => {
      if (configSyncTimerRef.current !== null) {
        window.clearTimeout(configSyncTimerRef.current);
        configSyncTimerRef.current = null;
      }
    };
  }, [appendClientLog, clearConfigSyncTimers, config, markConfigSyncSaved, t]);

  useEffect(() => {
    if (!backendContextReadyRef.current) {
      previousLlmProviderRef.current = config.llmProvider;
      return;
    }

    if (previousLlmProviderRef.current === config.llmProvider) {
      return;
    }

    previousLlmProviderRef.current = config.llmProvider;
    clearConfigSyncTimers();
    setConfigSyncState('saving');

    void updateConfig(configRef.current).then(nextConfig => {
      backendContextReadyRef.current = true;
      lastServerConfigRef.current = serializeServerConfig(nextConfig);
      startTransition(() => {
        setConfig(nextConfig);
      });
      markConfigSyncSaved();
    }).catch(error => {
      const message = error instanceof Error ? error.message : t('unknownError');
      setConfigSyncState('error');
      setMonitoringStatus(previousStatus => ({
        ...previousStatus,
        lastError: message,
      }));
      appendClientLog(t('logConfigSyncFailed'), LogLevel.ERROR, {
        error: message,
        scope: 'llmProviderImmediateSync',
      });
    });
  }, [appendClientLog, clearConfigSyncTimers, config.llmProvider, markConfigSyncSaved, t]);

  useEffect(() => {
    if (!backendContextReadyRef.current) {
      return;
    }
    void hydrateFromBackend(configRef.current.backendBaseUrl, { preserveRawFeed: true, sensorId: selectedSensorId });
  }, [hydrateFromBackend, selectedSensorId]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      void getBackendHealth(configRef.current.backendBaseUrl).then(() => {
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          backendReachable: true,
        }));
      }).catch(error => {
        const message = error instanceof Error ? error.message : t('unknownError');
        setMonitoringStatus(previousStatus => ({
          ...previousStatus,
          backendReachable: false,
          lastError: previousStatus.websocketConnected ? previousStatus.lastError : message,
        }));
      });
    }, 15000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [t]);

  useEffect(() => {
    if (!monitoringStatus.backendReachable || monitoringStatus.websocketConnected) {
      return;
    }

    const intervalId = window.setInterval(() => {
      void hydrateFromBackend(configRef.current.backendBaseUrl, {
        preserveRawFeed: true,
        sensorId: selectedSensorIdRef.current,
      });
    }, DISCONNECTED_REFRESH_INTERVAL_MS);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [hydrateFromBackend, monitoringStatus.backendReachable, monitoringStatus.websocketConnected]);

  useEffect(() => () => {
    isDisposedRef.current = true;
    clearConfigSyncTimers();
    closeTrafficSocket();
  }, [clearConfigSyncTimers, closeTrafficSocket]);

  const selectedProvider = getProviderDefinition(config.llmProvider);
  const selectedProviderSettings = getSelectedProviderSettings(config);
  const llmStatus = useMemo(
    () => ({
      loaded: monitoringStatus.backendReachable && Boolean(selectedProviderSettings.model),
      model: `${selectedProvider.label} / ${selectedProviderSettings.model || selectedProvider.defaultModel}`,
    }),
    [monitoringStatus.backendReachable, selectedProvider, selectedProviderSettings.model]
  );

  const sensorScopedTraffic = useMemo(
    () => (selectedSensorId ? liveTrafficFeed.filter(entry => entry.sensorId === selectedSensorId) : liveTrafficFeed),
    [liveTrafficFeed, selectedSensorId]
  );
  const sensorScopedLogs = useMemo(
    () => (selectedSensorId ? logs.filter(log => log.sensorId === selectedSensorId) : logs),
    [logs, selectedSensorId]
  );
  const sensorScopedArtifacts = useMemo(
    () => (selectedSensorId ? artifacts.filter(artifact => artifact.sensorId === selectedSensorId) : artifacts),
    [artifacts, selectedSensorId]
  );
  const sensorScopedSandboxAnalyses = useMemo(
    () => (selectedSensorId ? sandboxAnalyses.filter(analysis => analysis.sensorId === selectedSensorId) : sandboxAnalyses),
    [sandboxAnalyses, selectedSensorId]
  );
  const sensorScopedRawPackets = useMemo(
    () => (selectedSensorId ? rawPacketFeed.filter(packet => packet.sensorId === selectedSensorId) : rawPacketFeed),
    [rawPacketFeed, selectedSensorId]
  );

  const renderTab = () => {
    switch (activeTab) {
      case 'Dashboard':
        return (
          <Dashboard
            isMonitoring={monitoringStatus.captureRunning}
            captureActionPending={captureActionPending}
            replayActionPending={replayActionPending}
            onStartMonitoring={startMonitoring}
            onStopMonitoring={stopMonitoringGracefully}
            onStartReplay={startReplayCapture}
            onRevealProcessPath={revealProcessPath}
            onAnalyzeProcessInSandbox={analyzeProcessInSandbox}
            onAnalyzeUploadedFileInSandbox={analyzeUploadedFileInSandboxViaUi}
            onLoadSandboxLlmDebug={loadSandboxLlmDebug}
            onRetrySandboxAnalystReview={retrySandboxAnalystReviewViaUi}
            monitoringStatus={monitoringStatus}
            llmStatus={llmStatus}
            metricsSnapshot={metricsSnapshot}
            liveTrafficFeed={sensorScopedTraffic}
            rawPacketFeed={sensorScopedRawPackets}
            trafficMetrics={trafficMetrics}
            artifacts={sensorScopedArtifacts}
            sandboxAnalyses={sensorScopedSandboxAnalyses}
            rawFeedEnabled={config.liveRawFeedEnabled}
            getArtifactDownloadUrl={(artifactId) => getArtifactDownloadUrl(config.backendBaseUrl, artifactId)}
            getSandboxReportDownloadUrl={(analysisId) => getSandboxReportDownloadUrl(config.backendBaseUrl, analysisId)}
            sensors={sensors}
            selectedSensorId={selectedSensorId}
            onSelectSensor={setSelectedSensorId}
          />
        );
      case 'Rules':
        return (
          <RuleBuilder
            config={config}
            setConfig={setConfig}
            configSyncState={configSyncState}
          />
        );
      case 'Settings':
        return (
          <Settings
            config={config}
            setConfig={setConfig}
            availableInterfaces={availableInterfaces}
            monitoringStatus={monitoringStatus}
            refreshInterfaces={() => refreshInterfaces(true)}
            configSyncState={configSyncState}
            onRefreshThreatIntel={triggerThreatIntelRefresh}
            threatIntelRefreshPending={threatIntelRefreshPending}
            onApplySettingsNow={applySettingsNow}
            applySettingsPending={applySettingsPending}
            backendAppliedProviderLabel={backendAppliedProviderLabel}
          />
        );
      case 'Logs':
        return <Logs logs={sensorScopedLogs} sensors={sensors} selectedSensorId={selectedSensorId} onSelectSensor={setSelectedSensorId} />;
      case 'Fleet':
        return (
          <FleetManagement
            sensors={sensors}
            fleetStatus={monitoringStatus.fleetStatus}
            selectedSensorId={selectedSensorId}
            onSelectSensor={setSelectedSensorId}
          />
        );
      case 'ThreatHunt':
        return (
          <ThreatHunter
            backendBaseUrl={config.backendBaseUrl}
            selectedSensorId={selectedSensorId}
            sensors={sensors}
            onBeforeRun={syncConfigNow}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="flex min-h-screen bg-[#0D1117] text-gray-300 font-sans">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="flex-1 p-6 sm:p-8 lg:p-10">
        {renderTab()}
      </main>
    </div>
  );
};

export default App;
