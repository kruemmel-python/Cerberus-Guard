# CodeDump for Project: `Cerberus_Guard.zip`

_Generated on 2026-03-13T13:35:28.590Z_

## File: `App.tsx`  
- Path: `App.tsx`  
- Size: 26368 Bytes  
- Modified: 2026-03-13 14:23:38 UTC

```tsx
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
  getBootstrap,
  getBackendHealth,
  listCaptureInterfaces,
  revealLocalPath,
  startCapture,
  startReplay,
  stopCapture,
  updateConfig,
  getArtifactDownloadUrl,
  refreshThreatIntel,
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
  ReplayStatusPayload,
  SensorSummary,
  ThreatIntelStatus,
  TrafficLogEntry,
  TrafficMetricPoint,
} from './types';
import { useLocalization } from './hooks/useLocalization';
import { createId, getInitialConfig, saveClientPreferences } from './utils';

const MAX_LOG_ENTRIES = 500;
const MAX_FEED_ENTRIES = 100;
const MAX_ARTIFACT_ENTRIES = 50;
const MAX_RAW_FEED_ENTRIES = 25;
const CONFIG_SYNC_DELAY_MS = 700;
const BACKEND_SWITCH_DELAY_MS = 500;
const SOCKET_RECONNECT_DELAY_MS = 3000;

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
  const [availableInterfaces, setAvailableInterfaces] = useState<CaptureInterface[]>([]);
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus>(createInitialMonitoringStatus);
  const [metricsSnapshot, setMetricsSnapshot] = useState<MetricSnapshot>(createInitialMetricSnapshot);
  const [captureActionPending, setCaptureActionPending] = useState(false);
  const [replayActionPending, setReplayActionPending] = useState(false);
  const [configSyncState, setConfigSyncState] = useState<ConfigSyncState>('idle');
  const [sensors, setSensors] = useState<SensorSummary[]>([]);
  const [selectedSensorId, setSelectedSensorId] = useState<string | null>(null);
  const [threatIntelRefreshPending, setThreatIntelRefreshPending] = useState(false);
  const { t } = useLocalization();

  const websocketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const configSyncTimerRef = useRef<number | null>(null);
  const configSyncStateTimerRef = useRef<number | null>(null);
  const bootstrapRequestIdRef = useRef(0);
  const activeBaseUrlRef = useRef(config.backendBaseUrl);
  const configRef = useRef(config);
  const backendContextReadyRef = useRef(false);
  const isDisposedRef = useRef(false);
  const lastServerConfigRef = useRef(serializeServerConfig(config));
  const selectedSensorIdRef = useRef<string | null>(null);

  useEffect(() => {
    configRef.current = config;
  }, [config]);

  useEffect(() => {
    selectedSensorIdRef.current = selectedSensorId;
  }, [selectedSensorId]);

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

  const hydrateFromBackend = useCallback(async (baseUrl: string, options?: { preserveRawFeed?: boolean; sensorId?: string | null }) => {
    const requestId = ++bootstrapRequestIdRef.current;

    try {
      const payload = await getBootstrap(baseUrl, options?.sensorId ?? selectedSensorIdRef.current);
      if (isDisposedRef.current || requestId !== bootstrapRequestIdRef.current || payload.config.backendBaseUrl !== activeBaseUrlRef.current) {
        return;
      }

      backendContextReadyRef.current = true;
      lastServerConfigRef.current = serializeServerConfig(payload.config);
      setReplayActionPending(payload.replayStatus.state === 'running');

      startTransition(() => {
        setConfig(payload.config);
        setAvailableInterfaces(payload.interfaces);
        setLogs(payload.logs.slice(0, MAX_LOG_ENTRIES));
        setLiveTrafficFeed(payload.traffic.slice(0, MAX_FEED_ENTRIES));
        if (!options?.preserveRawFeed) {
          setRawPacketFeed([]);
        }
        setTrafficMetrics(payload.metricSeries);
        setArtifacts(payload.artifacts.slice(0, MAX_ARTIFACT_ENTRIES));
        setMetricsSnapshot(payload.metrics);
        setSensors(payload.sensors);
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

  const startMonitoring = useCallback(async () => {
    setCaptureActionPending(true);

    try {
      const response = await startCapture(configRef.current);
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
  }, [appendClientLog, applyCaptureStatus, t]);

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
      const response = await refreshThreatIntel(configRef.current.backendBaseUrl);
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
  }, [appendClientLog, t]);

  const revealProcessPath = useCallback(async (targetPath: string) => {
    try {
      await revealLocalPath(configRef.current.backendBaseUrl, targetPath);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('unknownError');
      appendClientLog(t('processActionFailed'), LogLevel.ERROR, { error: message, targetPath });
      throw error;
    }
  }, [appendClientLog, t]);

  useEffect(() => {
    activeBaseUrlRef.current = config.backendBaseUrl.trim() || 'http://localhost:8081';
    saveClientPreferences({ backendBaseUrl: activeBaseUrlRef.current });

    backendContextReadyRef.current = false;
    setMonitoringStatus(previousStatus => ({
      ...previousStatus,
      backendReachable: false,
      websocketConnected: false,
      lastError: null,
    }));

    const timeoutId = window.setTimeout(() => {
      closeTrafficSocket();
      void hydrateFromBackend(activeBaseUrlRef.current, { sensorId: selectedSensorIdRef.current });
      connectTrafficSocket(activeBaseUrlRef.current);
    }, BACKEND_SWITCH_DELAY_MS);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [config.backendBaseUrl, closeTrafficSocket, connectTrafficSocket, hydrateFromBackend]);

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
        setConfigSyncState('saved');
        configSyncStateTimerRef.current = window.setTimeout(() => {
          setConfigSyncState('idle');
          configSyncStateTimerRef.current = null;
        }, 1500);
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
  }, [appendClientLog, clearConfigSyncTimers, config, t]);

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
            monitoringStatus={monitoringStatus}
            llmStatus={llmStatus}
            metricsSnapshot={metricsSnapshot}
            liveTrafficFeed={sensorScopedTraffic}
            rawPacketFeed={sensorScopedRawPackets}
            trafficMetrics={trafficMetrics}
            artifacts={sensorScopedArtifacts}
            rawFeedEnabled={config.liveRawFeedEnabled}
            getArtifactDownloadUrl={(artifactId) => getArtifactDownloadUrl(config.backendBaseUrl, artifactId)}
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

```

## File: `Cerberus_Guard.zip`  
- Path: `Cerberus_Guard.zip`  
- Size: 152737 Bytes  
- Modified: 2026-03-13 14:34:36 UTC

> **Binary file skipped** (mode: skip).

## File: `components/Dashboard.tsx`  
- Path: `components/Dashboard.tsx`  
- Size: 31891 Bytes  
- Modified: 2026-03-13 14:23:32 UTC

```tsx
import React, { useMemo, useState } from 'react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  ActionType,
  AttackType,
  MetricSnapshot,
  MonitoringStatus,
  Packet,
  PcapArtifact,
  SensorSummary,
  TrafficLogEntry,
  TrafficMetricPoint,
} from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { StatCard } from './StatCard';

interface DashboardProps {
  isMonitoring: boolean;
  captureActionPending: boolean;
  replayActionPending: boolean;
  onStartMonitoring: () => void;
  onStopMonitoring: () => void;
  onStartReplay: (file: File, speedMultiplier: number) => Promise<void>;
  onRevealProcessPath: (targetPath: string) => Promise<void>;
  monitoringStatus: MonitoringStatus;
  llmStatus: { loaded: boolean; model: string };
  metricsSnapshot: MetricSnapshot;
  liveTrafficFeed: TrafficLogEntry[];
  rawPacketFeed: Packet[];
  trafficMetrics: TrafficMetricPoint[];
  artifacts: PcapArtifact[];
  rawFeedEnabled: boolean;
  getArtifactDownloadUrl: (artifactId: string) => string;
  sensors: SensorSummary[];
  selectedSensorId: string | null;
  onSelectSensor: (sensorId: string | null) => void;
}

const normalizeSearchValue = (value: string) => value.trim().toLowerCase();

const buildProcessSearchIndex = (entry: TrafficLogEntry) => {
  const localProcess = entry.packet.localProcess;
  if (!localProcess) {
    return '';
  }

  const serviceNames = localProcess.services.flatMap(service => [service.name, service.displayName, service.state]);
  return [
    localProcess.name,
    localProcess.executablePath,
    localProcess.commandLine,
    localProcess.companyName,
    localProcess.fileDescription,
    localProcess.signatureStatus,
    localProcess.signerSubject,
    localProcess.pid !== null ? String(localProcess.pid) : null,
    ...serviceNames,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
};

const matchesProcessFilter = (entry: TrafficLogEntry, filterValue: string) => {
  const normalizedFilter = normalizeSearchValue(filterValue);
  if (!normalizedFilter) {
    return true;
  }

  return buildProcessSearchIndex(entry).includes(normalizedFilter);
};

const getAttackTypeClass = (attackType: AttackType): string => {
  switch (attackType) {
    case AttackType.BRUTE_FORCE:
    case AttackType.DDOS:
      return 'text-red-400 font-semibold';
    case AttackType.MALICIOUS_PAYLOAD:
      return 'text-orange-400 font-semibold';
    case AttackType.PORT_SCAN:
      return 'text-yellow-400 font-semibold';
    case AttackType.NONE:
      return 'text-emerald-400';
    default:
      return 'text-gray-300';
  }
};

const getActionClass = (actionType: ActionType): string => {
  switch (actionType) {
    case ActionType.ALLOW:
      return 'bg-emerald-500/15 text-emerald-200';
    case ActionType.BLOCK:
      return 'bg-red-500/15 text-red-200';
    case ActionType.REDIRECT:
      return 'bg-orange-500/15 text-orange-200';
    default:
      return 'bg-gray-700 text-gray-300';
  }
};

const formatLocaleTimestamp = (isoString: string, localeCode: string) => {
  try {
    return new Intl.DateTimeFormat(localeCode, {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(isoString));
  } catch {
    return isoString;
  }
};

const formatBytes = (value: number) => {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
};

const ReplayStatusBadge: React.FC<{ monitoringStatus: MonitoringStatus }> = ({ monitoringStatus }) => {
  const { t } = useLocalization();
  const status = monitoringStatus.replayStatus.state;
  const statusClass =
    status === 'running'
      ? 'border-blue-500/30 bg-blue-500/15 text-blue-100'
      : status === 'completed'
        ? 'border-emerald-500/30 bg-emerald-500/15 text-emerald-100'
        : status === 'failed'
          ? 'border-red-500/30 bg-red-500/15 text-red-100'
          : 'border-gray-600/50 bg-gray-700/40 text-gray-300';

  return (
    <div className={`rounded-xl border px-4 py-3 text-sm ${statusClass}`}>
      <div className="font-semibold">{t('replayStatusLabel')}: {t(`replayState_${status}`)}</div>
      {monitoringStatus.replayStatus.fileName && (
        <div className="mt-1 text-xs opacity-80">
          {monitoringStatus.replayStatus.fileName}
          {monitoringStatus.replayStatus.totalPackets > 0 && ` • ${monitoringStatus.replayStatus.processedPackets}/${monitoringStatus.replayStatus.totalPackets}`}
        </div>
      )}
    </div>
  );
};

const TrafficRow: React.FC<{
  entry: TrafficLogEntry;
  getArtifactDownloadUrl: (artifactId: string) => string;
  onFilterByProcess: (value: string) => void;
  onCopyProcessPath: (targetPath: string) => Promise<void>;
  onRevealProcessPath: (targetPath: string) => Promise<void>;
}> = ({
  entry,
  getArtifactDownloadUrl,
  onFilterByProcess,
  onCopyProcessPath,
  onRevealProcessPath,
}) => {
  const { packet, attackType, confidence, action, explanation, decisionSource, pcapArtifactId, firewallApplied } = entry;
  const { t } = useLocalization();
  const layer7Protocol = packet.l7Protocol || 'UNKNOWN';
  const localProcess = packet.localProcess;
  const processTitle = localProcess
    ? [localProcess.executablePath, localProcess.commandLine].filter(Boolean).join('\n')
    : '';

  return (
    <tr className="border-b border-gray-700/40 bg-[#161B22] text-sm hover:bg-[#1a212c]">
      <td className="p-3 text-gray-400 whitespace-nowrap">{formatLocaleTimestamp(packet.timestamp, t('localeCode'))}</td>
      <td className="p-3">
        <div className="font-mono text-cyan-300 whitespace-nowrap">{packet.sourceIp}</div>
        <div className="text-[11px] text-gray-500">{entry.sensorName}</div>
      </td>
      <td className="p-3 font-mono text-purple-300 whitespace-nowrap">
        <div>{packet.destinationPort}</div>
        {localProcess && localProcess.localPort !== packet.destinationPort && (
          <div className="mt-1 text-[11px] text-gray-500">{t('processLocalPort')}: {localProcess.localPort}</div>
        )}
      </td>
      <td className="p-3 whitespace-nowrap">
        <div className="inline-flex items-center rounded-full bg-slate-800 px-2 py-1 text-xs font-semibold text-slate-200">
          {packet.protocol}
        </div>
        {layer7Protocol !== 'UNKNOWN' && (
          <div className="mt-1 text-[11px] uppercase tracking-wide text-sky-300">{layer7Protocol}</div>
        )}
      </td>
      <td className={`p-3 whitespace-nowrap ${getAttackTypeClass(attackType)}`}>{attackType.replace(/_/g, ' ').toUpperCase()}</td>
      <td className="p-3 whitespace-nowrap text-gray-300">{confidence.toFixed(2)}</td>
      <td className="p-3 max-w-sm text-gray-300" title={processTitle}>
        {localProcess ? (
          <>
            <div className="font-medium text-gray-100">
              {localProcess.name || t('processUnknown')}
              {localProcess.pid !== null ? ` (PID ${localProcess.pid})` : ''}
            </div>
            {(localProcess.companyName || localProcess.fileDescription) && (
              <div className="mt-1 text-[11px] text-gray-400">
                <span className="font-semibold text-gray-300">{t('processCompany')}:</span>{' '}
                {[localProcess.companyName, localProcess.fileDescription].filter(Boolean).join(' • ')}
              </div>
            )}
            {localProcess.signatureStatus && (
              <div className="mt-1 text-[11px] text-gray-400">
                <span className="font-semibold text-gray-300">{t('processSignature')}:</span>{' '}
                {localProcess.signatureStatus}
                {localProcess.signerSubject ? ` • ${localProcess.signerSubject}` : ''}
              </div>
            )}
            {localProcess.services.length > 0 && (
              <div className="mt-1 text-[11px] text-gray-400">
                <span className="font-semibold text-gray-300">{t('processServices')}:</span>{' '}
                {localProcess.services
                  .map(service => service.displayName || service.name)
                  .filter(Boolean)
                  .join(', ')}
              </div>
            )}
            <button
              type="button"
              onClick={() => {
                if (localProcess.executablePath) {
                  void onCopyProcessPath(localProcess.executablePath);
                }
              }}
              className="mt-1 block max-w-full truncate text-left text-[11px] text-blue-300 transition hover:text-blue-200"
              title={localProcess.executablePath || t('processPathUnavailable')}
              disabled={!localProcess.executablePath}
            >
              {localProcess.executablePath || t('processPathUnavailable')}
            </button>
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => onFilterByProcess(localProcess.name || localProcess.executablePath || String(localProcess.pid ?? ''))}
                className="rounded-md border border-gray-600 px-2 py-1 text-[11px] font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white"
              >
                {t('processFilterButton')}
              </button>
              {localProcess.executablePath && (
                <>
                  <button
                    type="button"
                    onClick={() => void onCopyProcessPath(localProcess.executablePath!)}
                    className="rounded-md border border-gray-600 px-2 py-1 text-[11px] font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white"
                  >
                    {t('processCopyPath')}
                  </button>
                  <button
                    type="button"
                    onClick={() => void onRevealProcessPath(localProcess.executablePath!)}
                    className="rounded-md border border-gray-600 px-2 py-1 text-[11px] font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white"
                  >
                    {t('processOpenFolder')}
                  </button>
                </>
              )}
            </div>
          </>
        ) : (
          <span className="text-gray-500">{t('processUnavailable')}</span>
        )}
      </td>
      <td className="p-3 whitespace-nowrap">
        <span className={`inline-flex rounded-full px-2 py-1 text-xs font-semibold ${getActionClass(entry.actionType)}`}>
          {action}
        </span>
        {firewallApplied && (
          <div className="mt-1 text-[11px] uppercase tracking-wide text-red-300">{t('firewallApplied')}</div>
        )}
      </td>
      <td className="p-3 whitespace-nowrap text-gray-400">{decisionSource.toUpperCase()}</td>
      <td className="p-3 max-w-md text-gray-400">
        <div className="truncate" title={explanation}>{explanation}</div>
        {pcapArtifactId && (
          <a
            href={getArtifactDownloadUrl(pcapArtifactId)}
            className="mt-1 inline-block text-xs font-semibold text-blue-300 transition hover:text-blue-200"
          >
            {t('downloadPcap')}
          </a>
        )}
      </td>
    </tr>
  );
};

const RawPacketRow: React.FC<{ packet: Packet }> = ({ packet }) => {
  const { t } = useLocalization();
  const metadataSummary = Object.entries(packet.l7Metadata ?? {})
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${value}`)
    .join(' • ');
  const layer7Protocol = packet.l7Protocol || 'UNKNOWN';

  return (
    <tr className="border-b border-gray-700/40 bg-[#161B22] text-sm">
      <td className="p-3 text-gray-400 whitespace-nowrap">{formatLocaleTimestamp(packet.timestamp, t('localeCode'))}</td>
      <td className="p-3 font-mono text-cyan-300 whitespace-nowrap">{packet.sourceIp}:{packet.sourcePort}</td>
      <td className="p-3 font-mono text-purple-300 whitespace-nowrap">{packet.destinationIp}:{packet.destinationPort}</td>
      <td className="p-3 whitespace-nowrap text-slate-200">{packet.protocol}</td>
      <td className="p-3 whitespace-nowrap text-sky-300">{layer7Protocol}</td>
      <td className="p-3 max-w-md truncate text-gray-400" title={metadataSummary || packet.payloadSnippet}>
        {metadataSummary || packet.payloadSnippet || '-'}
      </td>
    </tr>
  );
};

export const Dashboard: React.FC<DashboardProps> = ({
  isMonitoring,
  captureActionPending,
  replayActionPending,
  onStartMonitoring,
  onStopMonitoring,
  onStartReplay,
  onRevealProcessPath,
  monitoringStatus,
  llmStatus,
  metricsSnapshot,
  liveTrafficFeed,
  rawPacketFeed,
  trafficMetrics,
  artifacts,
  rawFeedEnabled,
  getArtifactDownloadUrl,
  sensors,
  selectedSensorId,
  onSelectSensor,
}) => {
  const { t } = useLocalization();
  const [selectedReplayFile, setSelectedReplayFile] = useState<File | null>(null);
  const [replaySpeed, setReplaySpeed] = useState(10);
  const [processFilter, setProcessFilter] = useState('');
  const [processActionState, setProcessActionState] = useState<{ tone: 'success' | 'error'; message: string } | null>(null);

  const chartData = useMemo(
    () => trafficMetrics.map(metric => ({
      ...metric,
      label: formatLocaleTimestamp(metric.bucketStart, t('localeCode')),
    })),
    [t, trafficMetrics]
  );
  const filteredLiveTrafficFeed = useMemo(
    () => liveTrafficFeed.filter(entry => matchesProcessFilter(entry, processFilter)),
    [liveTrafficFeed, processFilter]
  );

  const handleCopyProcessPath = async (targetPath: string) => {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('Clipboard API unavailable.');
      }

      await navigator.clipboard.writeText(targetPath);
      setProcessActionState({
        tone: 'success',
        message: t('processActionCopied'),
      });
    } catch {
      setProcessActionState({
        tone: 'error',
        message: t('processActionFailed'),
      });
    }
  };

  const handleRevealProcessPath = async (targetPath: string) => {
    try {
      await onRevealProcessPath(targetPath);
      setProcessActionState({
        tone: 'success',
        message: t('processActionOpened'),
      });
    } catch {
      setProcessActionState({
        tone: 'error',
        message: t('processActionFailed'),
      });
    }
  };

  const handleReplaySubmit = async () => {
    if (!selectedReplayFile) {
      return;
    }

    await onStartReplay(selectedReplayFile, replaySpeed);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-4xl font-bold text-white">{t('dashboardTitle')}</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('dashboardDescription')}</p>
      </div>

      <div className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-5 shadow-xl">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="text-sm font-medium text-gray-400">{t('sensorScopeLabel')}</div>
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                onClick={() => onSelectSensor(null)}
                className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                  selectedSensorId === null ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
                }`}
              >
                {t('fleetAllSensors')}
              </button>
              {sensors.map(sensor => (
                <button
                  key={sensor.id}
                  onClick={() => onSelectSensor(sensor.id)}
                  className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                    selectedSensorId === sensor.id ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
                  }`}
                >
                  {sensor.name}
                </button>
              ))}
            </div>
          </div>
          <div className="text-sm text-gray-400">
            {selectedSensorId
              ? t('sensorScopeSelected', { sensorName: sensors.find(sensor => sensor.id === selectedSensorId)?.name || selectedSensorId })
              : t('sensorScopeGlobal')}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-6">
        <StatCard
          title={t('monitoringStatusCardTitle')}
          value={isMonitoring ? t('activeStatus') : t('stoppedStatus')}
          description={monitoringStatus.activeDevice ? `${t('captureDeviceLabel')}: ${monitoringStatus.activeDevice}` : t('captureIdle')}
          valueColor={isMonitoring ? 'text-emerald-400' : 'text-red-400'}
        />
        <StatCard
          title={t('backendStatusCardTitle')}
          value={monitoringStatus.backendReachable ? t('connectedStatus') : t('disconnectedStatus')}
          description={monitoringStatus.websocketConnected ? t('streamConnected') : t('streamDisconnected')}
          valueColor={monitoringStatus.backendReachable ? 'text-emerald-400' : 'text-red-400'}
        />
        <StatCard
          title={t('llmStatusCardTitle')}
          value={llmStatus.loaded ? t('loadedStatus') : t('errorStatus')}
          description={llmStatus.model}
          valueColor={llmStatus.loaded ? 'text-emerald-400' : 'text-red-400'}
        />
        <StatCard
          title={t('packetsProcessedCardTitle')}
          value={metricsSnapshot.packetsProcessed.toLocaleString()}
          description={t('persistedHistoryBackend')}
          valueColor="text-blue-400"
        />
        <StatCard
          title={t('threatsDetectedCardTitle')}
          value={metricsSnapshot.threatsDetected.toLocaleString()}
          description={t('last24Hours')}
          valueColor="text-orange-400"
        />
        <StatCard
          title={t('blockedDecisionsCardTitle')}
          value={metricsSnapshot.blockedDecisions.toLocaleString()}
          description={t('lifetimeCounter')}
          valueColor="text-red-400"
        />
      </div>

      <div className="flex flex-col gap-4 rounded-2xl border border-gray-700/60 bg-[#161B22] p-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={onStartMonitoring}
            disabled={isMonitoring || captureActionPending || replayActionPending || !monitoringStatus.backendReachable}
            className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-700"
          >
            {captureActionPending && !isMonitoring ? t('startingStatus') : t('startMonitoringButton')}
          </button>
          <button
            onClick={onStopMonitoring}
            disabled={!isMonitoring || captureActionPending}
            className="rounded-lg bg-gray-700 px-4 py-2 font-semibold text-white transition hover:bg-gray-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {captureActionPending && isMonitoring ? t('stoppingStatus') : t('stopMonitoringButton')}
          </button>
          <div className="text-sm text-gray-400">
            {monitoringStatus.activeFilter ? `${t('captureFilterLabel')}: ${monitoringStatus.activeFilter}` : t('captureFilterUnset')}
          </div>
        </div>

        <div className="flex flex-col gap-3 lg:items-end">
          <ReplayStatusBadge monitoringStatus={monitoringStatus} />
          {monitoringStatus.lastError && <div className="text-sm text-red-300">{monitoringStatus.lastError}</div>}
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <StatCard
          title={t('fleetStatusLabel')}
          value={monitoringStatus.fleetStatus.deploymentMode}
          description={monitoringStatus.fleetStatus.connectedToHub ? t('fleetConnectedHub') : t('fleetStandaloneHint')}
          valueColor="text-cyan-300"
        />
        <StatCard
          title={t('threatIntelStatusLabel')}
          value={monitoringStatus.threatIntelStatus.enabled ? t('activeStatus') : t('stoppedStatus')}
          description={`${monitoringStatus.threatIntelStatus.loadedIndicators.toLocaleString()} ${t('threatIntelIndicatorsLoaded')}`}
          valueColor={monitoringStatus.threatIntelStatus.enabled ? 'text-emerald-400' : 'text-gray-400'}
        />
        <StatCard
          title={t('fleetSensorsConnected')}
          value={monitoringStatus.fleetStatus.connectedSensors.toLocaleString()}
          description={monitoringStatus.fleetStatus.hubUrl || t('fleetNoHubConfigured')}
          valueColor="text-purple-300"
        />
      </div>

      <div className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-4 shadow-xl">
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-white">{t('trafficTrendTitle')}</h2>
          <p className="text-sm text-gray-400">{t('trafficTrendDescription')}</p>
        </div>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
              <XAxis dataKey="label" stroke="#9CA3AF" minTickGap={24} />
              <YAxis stroke="#9CA3AF" allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: 16 }}
                labelStyle={{ color: '#F9FAFB' }}
              />
              <Legend />
              <Line type="monotone" dataKey="trafficCount" name={t('trafficCountSeries')} stroke="#60A5FA" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="threatCount" name={t('threatCountSeries')} stroke="#FB923C" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="blockedCount" name={t('blockedCountSeries')} stroke="#F87171" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.1fr_1fr]">
        <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-5 shadow-xl">
          <h2 className="text-xl font-semibold text-white">{t('replayTitle')}</h2>
          <p className="mt-2 text-sm text-gray-400">{t('replayDescription')}</p>

          <div className="mt-5 grid gap-4 md:grid-cols-[1.2fr_0.7fr_auto]">
            <div>
              <label className="mb-2 block text-sm font-medium text-gray-400">{t('pcapFileLabel')}</label>
              <input
                type="file"
                accept=".pcap,.cap"
                onChange={event => setSelectedReplayFile(event.target.files?.[0] ?? null)}
                className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-gray-300 file:mr-4 file:rounded-md file:border-0 file:bg-blue-600 file:px-3 file:py-2 file:text-sm file:font-semibold file:text-white"
              />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-gray-400">{t('replaySpeedLabel')}</label>
              <input
                type="number"
                min="1"
                max="100"
                value={replaySpeed}
                onChange={event => setReplaySpeed(Number.parseInt(event.target.value, 10) || 1)}
                className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={() => void handleReplaySubmit()}
                disabled={!selectedReplayFile || replayActionPending || isMonitoring}
                className="w-full rounded-lg bg-orange-600 px-4 py-2 font-semibold text-white transition hover:bg-orange-700 disabled:cursor-not-allowed disabled:bg-gray-700"
              >
                {replayActionPending ? t('replayRunning') : t('startReplayButton')}
              </button>
            </div>
          </div>

          <div className="mt-5 rounded-xl border border-gray-700 bg-gray-900/50 p-4 text-sm text-gray-400">
            <div>{t('replayHint')}</div>
            {monitoringStatus.replayStatus.message && (
              <div className="mt-2 text-red-300">{monitoringStatus.replayStatus.message}</div>
            )}
          </div>
        </section>

        <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-5 shadow-xl">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">{t('forensicsTitle')}</h2>
              <p className="mt-2 text-sm text-gray-400">{t('forensicsDescription')}</p>
            </div>
          </div>

          <div className="mt-5 space-y-3">
            {artifacts.length === 0 && (
              <div className="rounded-xl border border-dashed border-gray-700 p-6 text-center text-sm text-gray-500">
                {t('noArtifactsYet')}
              </div>
            )}

            {artifacts.map(artifact => (
              <div key={artifact.id} className="rounded-xl border border-gray-700 bg-gray-900/40 p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <div className="text-sm font-semibold text-white">{artifact.fileName}</div>
                    <div className="mt-1 text-xs text-gray-400">
                      {formatLocaleTimestamp(artifact.createdAt, t('localeCode'))} • {artifact.sourceIp} • {artifact.sensorName} • {artifact.packetCount} {t('packetsLabel')} • {formatBytes(artifact.bytes)}
                    </div>
                    <div className={`mt-2 text-sm ${getAttackTypeClass(artifact.attackType)}`}>
                      {artifact.attackType.replace(/_/g, ' ').toUpperCase()}
                    </div>
                  </div>
                  <a
                    href={getArtifactDownloadUrl(artifact.id)}
                    className="rounded-lg bg-blue-600 px-4 py-2 text-center text-sm font-semibold text-white transition hover:bg-blue-700"
                  >
                    {t('downloadPcap')}
                  </a>
                </div>
                <div className="mt-3 text-sm text-gray-400">{artifact.explanation}</div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
        <div className="border-b border-gray-700/50 p-4">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">{t('liveTrafficFeed')}</h2>
            </div>
            <div className="flex flex-col gap-3 xl:min-w-[30rem]">
              <label className="text-xs font-semibold uppercase tracking-wide text-gray-400" htmlFor="process-filter">
                {t('processFilterLabel')}
              </label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  id="process-filter"
                  value={processFilter}
                  onChange={event => setProcessFilter(event.target.value)}
                  placeholder={t('processFilterPlaceholder')}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setProcessFilter('')}
                  disabled={!processFilter}
                  className="rounded-lg border border-gray-600 px-3 py-2 text-sm font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {t('processFilterClear')}
                </button>
              </div>
              {processActionState && (
                <div className={`text-xs ${processActionState.tone === 'success' ? 'text-emerald-300' : 'text-red-300'}`}>
                  {processActionState.message}
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-800/30">
              <tr>
                {[
                  'colTimestamp',
                  'colSourceIp',
                  'colDestPort',
                  'colProtocol',
                  'colAttackType',
                  'colConfidence',
                  'colProcess',
                  'colAction',
                  'colDecisionSource',
                  'colLlmExplanation',
                ].map(headerKey => (
                  <th key={headerKey} className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                    {t(headerKey)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {filteredLiveTrafficFeed.length > 0 ? (
                filteredLiveTrafficFeed.map(entry => (
                  <TrafficRow
                    key={entry.id}
                    entry={entry}
                    getArtifactDownloadUrl={getArtifactDownloadUrl}
                    onFilterByProcess={setProcessFilter}
                    onCopyProcessPath={handleCopyProcessPath}
                    onRevealProcessPath={handleRevealProcessPath}
                  />
                ))
              ) : (
                <tr>
                  <td colSpan={10} className="p-8 text-center text-gray-500">
                    {liveTrafficFeed.length > 0 && processFilter
                      ? t('processNoFilterMatches')
                      : isMonitoring
                        ? t('waitingForTraffic')
                        : t('startMonitoringToSeeTraffic')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {rawFeedEnabled && (
        <div className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
          <div className="border-b border-gray-700/50 p-4">
            <h2 className="text-xl font-semibold text-white">{t('rawFeedTitle')}</h2>
            <p className="mt-1 text-sm text-gray-400">{t('rawFeedDescription')}</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-800/30">
                <tr>
                  {['colTimestamp', 'rawFeedSource', 'rawFeedDestination', 'colProtocol', 'rawFeedL7', 'rawFeedMetadata'].map(headerKey => (
                    <th key={headerKey} className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                      {t(headerKey)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {rawPacketFeed.length > 0 ? (
                  rawPacketFeed.map(packet => <RawPacketRow key={packet.id} packet={packet} />)
                ) : (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-gray-500">{t('rawFeedEmpty')}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

```

## File: `components/FleetManagement.tsx`  
- Path: `components/FleetManagement.tsx`  
- Size: 5195 Bytes  
- Modified: 2026-03-13 13:07:54 UTC

```tsx
import React from 'react';
import { FleetStatusPayload, SensorSummary } from '../types';
import { useLocalization } from '../hooks/useLocalization';

interface FleetManagementProps {
  sensors: SensorSummary[];
  fleetStatus: FleetStatusPayload;
  selectedSensorId: string | null;
  onSelectSensor: (sensorId: string | null) => void;
}

const formatTimestamp = (value: string | null, localeCode: string) => {
  if (!value) {
    return '-';
  }

  try {
    return new Intl.DateTimeFormat(localeCode, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(value));
  } catch {
    return value;
  }
};

export const FleetManagement: React.FC<FleetManagementProps> = ({
  sensors,
  fleetStatus,
  selectedSensorId,
  onSelectSensor,
}) => {
  const { t } = useLocalization();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('fleetTitle')}</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('fleetDescription')}</p>
        </div>
        <div className="rounded-xl border border-gray-700 bg-[#161B22] px-4 py-3 text-sm text-gray-300">
          <div>{t('fleetModeLabel')}: <span className="font-semibold text-white">{fleetStatus.deploymentMode}</span></div>
          <div className="mt-1">{t('fleetSensorsConnected')}: <span className="font-semibold text-white">{fleetStatus.connectedSensors}</span></div>
        </div>
      </div>

      <div className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-5">
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => onSelectSensor(null)}
            className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
              selectedSensorId === null ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
            }`}
          >
            {t('fleetAllSensors')}
          </button>
          {sensors.map(sensor => (
            <button
              key={sensor.id}
              onClick={() => onSelectSensor(sensor.id)}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                selectedSensorId === sensor.id ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
              }`}
            >
              {sensor.name}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
        <div className="border-b border-gray-700/50 p-4">
          <h3 className="text-xl font-semibold text-white">{t('fleetSensorsTable')}</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-800/30">
              <tr>
                {['fleetColSensor', 'fleetColMode', 'fleetColStatus', 'fleetColCapture', 'packetsProcessedCardTitle', 'threatsDetectedCardTitle', 'blockedDecisionsCardTitle', 'fleetColLastSeen'].map(header => (
                  <th key={header} className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                    {t(header)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {sensors.length === 0 && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-gray-500">{t('fleetNoSensors')}</td>
                </tr>
              )}
              {sensors.map(sensor => (
                <tr key={sensor.id} className="bg-[#161B22] text-sm hover:bg-[#1a212c]">
                  <td className="p-3">
                    <div className="font-semibold text-white">{sensor.name}</div>
                    <div className="text-xs text-gray-500">{sensor.id}</div>
                  </td>
                  <td className="p-3 text-gray-300">{sensor.mode}</td>
                  <td className="p-3">
                    <span className={`inline-flex rounded-full px-2 py-1 text-xs font-semibold ${
                      sensor.connected ? 'bg-emerald-500/15 text-emerald-200' : 'bg-red-500/15 text-red-200'
                    }`}>
                      {sensor.connected ? t('connectedStatus') : t('disconnectedStatus')}
                    </span>
                  </td>
                  <td className="p-3 text-gray-300">{sensor.captureRunning ? t('activeStatus') : t('stoppedStatus')}</td>
                  <td className="p-3 text-blue-300">{sensor.packetsProcessed.toLocaleString()}</td>
                  <td className="p-3 text-orange-300">{sensor.threatsDetected.toLocaleString()}</td>
                  <td className="p-3 text-red-300">{sensor.blockedDecisions.toLocaleString()}</td>
                  <td className="p-3 text-gray-400">{formatTimestamp(sensor.lastSeenAt, t('localeCode'))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

```

## File: `components/Header.tsx`  
- Path: `components/Header.tsx`  
- Size: 5523 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```tsx

import React from 'react';
import { useLocalization, Language } from '../hooks/useLocalization';

interface HeaderProps {
  isMonitoring: boolean;
  setIsMonitoring: (isMonitoring: boolean) => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

const PlayIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
    <path d="M8 5v14l11-7z" />
  </svg>
);

const PauseIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
  </svg>
);

const ShieldIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
    </svg>
);

const GlobeIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 21l5.25-11.25L21 21m-9-3h7.5M3 5.621a48.474 48.474 0 016-.371m0 0c1.12 0 2.233.038 3.334.114M9 5.25V3m3.334 2.364C11.176 10.658 7.69 15.08 3 17.502m9.334-12.138c.896.061 1.785.147 2.666.257m-4.589 8.495a18.023 18.023 0 01-3.827-5.802" />
    </svg>
);


export const Header: React.FC<HeaderProps> = ({ isMonitoring, setIsMonitoring, activeTab, setActiveTab }) => {
  const { t, changeLanguage, currentLanguage, languages } = useLocalization();
  
  const tabKeys: { [key: string]: string } = {
    Dashboard: 'dashboardTab',
    Settings: 'settingsTab',
    Logs: 'logsTab'
  }

  const handleLanguageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    changeLanguage(e.target.value as Language);
  };

  return (
    <header className="bg-gray-800 shadow-lg">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          <div className="flex items-center space-x-4">
            <ShieldIcon className="h-8 w-8 text-blue-400"/>
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wider">{t('headerTitle')}</h1>
            <div className="hidden sm:flex items-center space-x-2">
              <span className={`h-3 w-3 rounded-full ${isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></span>
              <span className="text-sm font-medium text-gray-400">{isMonitoring ? t('monitoringStatus') : t('stoppedStatus')}</span>
            </div>
          </div>
          <div className="flex items-center space-x-2 sm:space-x-4">
            <div className="relative">
                <GlobeIcon className="absolute left-2 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400 pointer-events-none"/>
                <select 
                    value={currentLanguage} 
                    onChange={handleLanguageChange}
                    className="appearance-none bg-gray-700 text-white rounded-md pl-8 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                >
                    {Object.entries(languages).map(([code, name]) => (
                        <option key={code} value={code}>{name}</option>
                    ))}
                </select>
            </div>
            <nav className="hidden md:flex space-x-2 bg-gray-700 p-1 rounded-lg">
              {Object.keys(tabKeys).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-sm font-medium rounded-md transition-colors duration-200 ${
                    activeTab === tab ? 'bg-blue-500 text-white shadow' : 'text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {t(tabKeys[tab])}
                </button>
              ))}
            </nav>
            <button
              onClick={() => setIsMonitoring(!isMonitoring)}
              className={`flex items-center justify-center w-12 h-12 rounded-full transition-colors duration-300 ${
                isMonitoring
                  ? 'bg-yellow-500 hover:bg-yellow-600 text-white'
                  : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
              aria-label={isMonitoring ? t('stopMonitoring') : t('startMonitoring')}
            >
              {isMonitoring ? <PauseIcon className="h-6 w-6"/> : <PlayIcon className="h-6 w-6"/>}
            </button>
          </div>
        </div>
        <div className="md:hidden flex justify-center pb-2">
           <nav className="flex space-x-1 bg-gray-700 p-1 rounded-lg w-full justify-around">
              {Object.keys(tabKeys).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-3 py-2 text-xs font-medium rounded-md transition-colors duration-200 w-full text-center ${
                    activeTab === tab ? 'bg-blue-500 text-white shadow' : 'text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {t(tabKeys[tab])}
                </button>
              ))}
            </nav>
        </div>
      </div>
    </header>
  );
};
```

## File: `components/Logs.tsx`  
- Path: `components/Logs.tsx`  
- Size: 5031 Bytes  
- Modified: 2026-03-13 13:10:16 UTC

```tsx
import React, { useState } from 'react';
import { LogEntry, LogLevel, SensorSummary } from '../types';
import { useLocalization } from '../hooks/useLocalization';

interface LogsProps {
  logs: LogEntry[];
  sensors: SensorSummary[];
  selectedSensorId: string | null;
  onSelectSensor: (sensorId: string | null) => void;
}

const getLogLevelColor = (level: LogLevel): string => {
  switch (level) {
    case LogLevel.INFO:
      return 'text-blue-400';
    case LogLevel.WARN:
      return 'text-yellow-400';
    case LogLevel.ERROR:
      return 'text-orange-400';
    case LogLevel.CRITICAL:
      return 'text-red-500 font-bold';
    default:
      return 'text-gray-400';
  }
};

const formatTimestamp = (isoString: string): string => {
  const date = new Date(isoString);
  const hours = date.getHours().toString().padStart(2, '0');
  const minutes = date.getMinutes().toString().padStart(2, '0');
  const seconds = date.getSeconds().toString().padStart(2, '0');
  const milliseconds = date.getMilliseconds().toString().padStart(3, '0');
  return `${hours}:${minutes}:${seconds}.${milliseconds}`;
};

const LogRow: React.FC<{ log: LogEntry }> = ({ log }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <>
      <tr className="cursor-pointer bg-gray-800 transition-colors duration-200 hover:bg-gray-700/50" onClick={() => setIsExpanded(!isExpanded)}>
        <td className="p-3 text-sm whitespace-nowrap text-gray-500">{formatTimestamp(log.timestamp)}</td>
        <td className={`p-3 text-sm font-semibold whitespace-nowrap ${getLogLevelColor(log.level)}`}>{log.level}</td>
        <td className="p-3 text-sm text-gray-400">{log.sensorName || '-'}</td>
        <td className="w-full p-3 text-sm text-gray-300">{log.message}</td>
        <td className="p-3 text-center text-sm text-gray-500">
          {log.details && <span className="text-gray-400">{isExpanded ? '▼' : '►'}</span>}
        </td>
      </tr>
      {isExpanded && log.details && (
        <tr className="bg-gray-800/50">
          <td colSpan={5} className="p-4">
            <pre className="overflow-x-auto rounded-md bg-gray-900 p-4 font-mono text-xs text-green-300">
              {JSON.stringify(log.details, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
};

export const Logs: React.FC<LogsProps> = ({ logs, sensors, selectedSensorId, onSelectSensor }) => {
  const { t } = useLocalization();
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="mb-2 text-3xl font-bold text-white">{t('logsTitle')}</h2>
          <p className="text-sm text-gray-400">{t('logsDescription')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSelectSensor(null)}
            className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
              selectedSensorId === null ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
            }`}
          >
            {t('fleetAllSensors')}
          </button>
          {sensors.map(sensor => (
            <button
              key={sensor.id}
              onClick={() => onSelectSensor(sensor.id)}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                selectedSensorId === sensor.id ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
              }`}
            >
              {sensor.name}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-lg bg-gray-800 shadow-xl">
        <div className="overflow-x-auto max-h-[75vh]">
          <table className="w-full">
            <thead className="sticky top-0 bg-gray-700">
              <tr>
                <th className="w-32 p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('colTimestamp')}</th>
                <th className="w-32 p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('colLevel')}</th>
                <th className="w-48 p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('fleetColSensor')}</th>
                <th className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('colMessage')}</th>
                <th className="w-16 p-3 text-center text-xs font-medium uppercase tracking-wider text-gray-300">{t('colDetails')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {logs.length > 0 ? (
                logs.map(log => <LogRow key={log.id} log={log} />)
              ) : (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-gray-500">
                    {t('noLogsYet')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

```

## File: `components/RuleBuilder.tsx`  
- Path: `components/RuleBuilder.tsx`  
- Size: 15759 Bytes  
- Modified: 2026-03-13 13:14:20 UTC

```tsx
import React from 'react';
import { ActionType, AttackType, Configuration, CustomRule, CustomRuleCondition } from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { createId } from '../utils';

interface RuleBuilderProps {
  config: Configuration;
  setConfig: React.Dispatch<React.SetStateAction<Configuration>>;
  configSyncState: 'idle' | 'saving' | 'saved' | 'error';
}

const FIELD_OPTIONS: CustomRuleCondition['field'][] = [
  'sourceIp',
  'destinationIp',
  'sourcePort',
  'destinationPort',
  'protocol',
  'direction',
  'size',
  'l7Protocol',
  'payloadSnippet',
  'l7.host',
  'l7.path',
  'l7.userAgent',
  'l7.dnsQuery',
  'l7.sni',
  'l7.sshBanner',
  'l7.ftpCommand',
  'l7.rdpCookie',
  'l7.smbCommand',
  'l7.sqlOperation',
];

const OPERATOR_OPTIONS: CustomRuleCondition['operator'][] = [
  'equals',
  'not_equals',
  'greater_than',
  'less_than',
  'contains',
  'starts_with',
  'in_cidr',
  'not_in_cidr',
  'in_list',
  'not_in_list',
];

const createDefaultCondition = (): CustomRuleCondition => ({
  id: createId(),
  field: 'destinationPort',
  operator: 'equals',
  value: '3389',
});

const createDefaultRule = (name: string, explanation: string): CustomRule => ({
  id: createId(),
  name,
  enabled: true,
  matchMode: 'all',
  conditions: [createDefaultCondition()],
  outcome: {
    actionType: ActionType.BLOCK,
    attackType: AttackType.OTHER,
    confidence: 0.9,
    explanation,
    needsDeepInspection: false,
  },
});

const InputLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-gray-400">{children}</label>
);

const SyncBadge: React.FC<{ state: RuleBuilderProps['configSyncState']; label: string }> = ({ state, label }) => {
  const colorClass =
    state === 'saving'
      ? 'border-yellow-500/30 bg-yellow-500/15 text-yellow-100'
      : state === 'saved'
        ? 'border-emerald-500/30 bg-emerald-500/15 text-emerald-100'
        : state === 'error'
          ? 'border-red-500/30 bg-red-500/15 text-red-100'
          : 'border-gray-600/50 bg-gray-700/50 text-gray-300';

  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${colorClass}`}>
      {label}
    </span>
  );
};

export const RuleBuilder: React.FC<RuleBuilderProps> = ({ config, setConfig, configSyncState }) => {
  const { t } = useLocalization();

  const updateRule = (ruleId: string, updater: (rule: CustomRule) => CustomRule) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      customRules: previousConfig.customRules.map(rule => (rule.id === ruleId ? updater(rule) : rule)),
    }));
  };

  const addRule = () => {
    setConfig(previousConfig => ({
      ...previousConfig,
      customRules: [...previousConfig.customRules, createDefaultRule(t('newCustomRuleName'), t('newCustomRuleExplanation'))],
    }));
  };

  const removeRule = (ruleId: string) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      customRules: previousConfig.customRules.filter(rule => rule.id !== ruleId),
    }));
  };

  const addCondition = (ruleId: string) => {
    updateRule(ruleId, rule => ({
      ...rule,
      conditions: [...rule.conditions, createDefaultCondition()],
    }));
  };

  const updateCondition = (ruleId: string, conditionId: string, patch: Partial<CustomRuleCondition>) => {
    updateRule(ruleId, rule => ({
      ...rule,
      conditions: rule.conditions.map(condition =>
        condition.id === conditionId
          ? {
              ...condition,
              ...patch,
            }
          : condition
      ),
    }));
  };

  const removeCondition = (ruleId: string, conditionId: string) => {
    updateRule(ruleId, rule => ({
      ...rule,
      conditions: rule.conditions.filter(condition => condition.id !== conditionId),
    }));
  };

  const syncStateLabel =
    configSyncState === 'saving'
      ? t('configSyncSaving')
      : configSyncState === 'saved'
        ? t('configSyncSaved')
        : configSyncState === 'error'
          ? t('configSyncError')
          : t('configSyncIdle');

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('rulesTitle')}</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('rulesDescription')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <SyncBadge state={configSyncState} label={syncStateLabel} />
          <button
            onClick={addRule}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
          >
            {t('addRule')}
          </button>
        </div>
      </div>

      {config.customRules.length === 0 && (
        <div className="rounded-2xl border border-dashed border-gray-700 bg-[#161B22] p-10 text-center text-sm text-gray-500">
          {t('rulesEmptyState')}
        </div>
      )}

      {config.customRules.map(rule => (
        <section key={rule.id} className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="grid flex-1 grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <InputLabel>{t('ruleName')}</InputLabel>
                <input
                  type="text"
                  value={rule.name}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, name: event.target.value }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div>
                <InputLabel>{t('ruleMatchMode')}</InputLabel>
                <select
                  value={rule.matchMode}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, matchMode: event.target.value as CustomRule['matchMode'] }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="all">{t('ruleMatchModeAll')}</option>
                  <option value="any">{t('ruleMatchModeAny')}</option>
                </select>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <label className="flex items-center gap-3 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, enabled: event.target.checked }))}
                  className="h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500"
                />
                {t('ruleEnabled')}
              </label>
              <button
                onClick={() => removeRule(rule.id)}
                className="rounded-lg border border-red-500/40 px-3 py-2 text-sm font-semibold text-red-300 transition hover:bg-red-500/10"
              >
                {t('removeRule')}
              </button>
            </div>
          </div>

          <div className="mt-6 rounded-2xl border border-gray-700/60 bg-gray-900/40 p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">{t('ruleConditions')}</h3>
                <p className="mt-1 text-sm text-gray-400">{t('ruleConditionsHint')}</p>
              </div>
              <button
                onClick={() => addCondition(rule.id)}
                className="rounded-lg bg-gray-700 px-3 py-2 text-sm font-semibold text-white transition hover:bg-gray-600"
              >
                {t('addCondition')}
              </button>
            </div>

            <div className="space-y-4">
              {rule.conditions.map(condition => (
                <div key={condition.id} className="grid gap-4 rounded-xl border border-gray-700 bg-[#11161d] p-4 lg:grid-cols-[1.2fr_1fr_1.2fr_auto]">
                  <div>
                    <InputLabel>{t('ruleField')}</InputLabel>
                    <select
                      value={condition.field}
                      onChange={event => updateCondition(rule.id, condition.id, { field: event.target.value as CustomRuleCondition['field'] })}
                      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                    >
                      {FIELD_OPTIONS.map(field => (
                        <option key={field} value={field}>{t(`ruleField_${field}`)}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <InputLabel>{t('ruleOperator')}</InputLabel>
                    <select
                      value={condition.operator}
                      onChange={event => updateCondition(rule.id, condition.id, { operator: event.target.value as CustomRuleCondition['operator'] })}
                      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                    >
                      {OPERATOR_OPTIONS.map(operator => (
                        <option key={operator} value={operator}>{t(`ruleOperator_${operator}`)}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <InputLabel>{t('ruleValue')}</InputLabel>
                    <input
                      type="text"
                      value={condition.value}
                      onChange={event => updateCondition(rule.id, condition.id, { value: event.target.value })}
                      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                    />
                  </div>

                  <div className="flex items-end">
                    <button
                      onClick={() => removeCondition(rule.id, condition.id)}
                      disabled={rule.conditions.length === 1}
                      className="w-full rounded-lg border border-gray-600 px-3 py-2 text-sm font-semibold text-gray-300 transition hover:border-red-500 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {t('remove')}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-6 rounded-2xl border border-gray-700/60 bg-gray-900/40 p-5">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-white">{t('ruleOutcome')}</h3>
              <p className="mt-1 text-sm text-gray-400">{t('ruleOutcomeHint')}</p>
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div>
                <InputLabel>{t('ruleAction')}</InputLabel>
                <select
                  value={rule.outcome.actionType}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, actionType: event.target.value as ActionType } }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value={ActionType.ALLOW}>{t('ruleAction_allow')}</option>
                  <option value={ActionType.BLOCK}>{t('ruleAction_block')}</option>
                  <option value={ActionType.REDIRECT}>{t('ruleAction_redirect')}</option>
                </select>
              </div>

              <div>
                <InputLabel>{t('ruleAttackType')}</InputLabel>
                <select
                  value={rule.outcome.attackType}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, attackType: event.target.value as AttackType } }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  {Object.values(AttackType).map(attackType => (
                    <option key={attackType} value={attackType}>{t(`attackType_${attackType}`)}</option>
                  ))}
                </select>
              </div>

              <div>
                <InputLabel>{t('ruleConfidence')}</InputLabel>
                <div className="rounded-lg border border-gray-600 bg-gray-900 px-3 py-2">
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    value={rule.outcome.confidence}
                    onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, confidence: Number.parseFloat(event.target.value) } }))}
                    className="w-full"
                  />
                  <div className="mt-2 text-sm font-semibold text-blue-300">{(rule.outcome.confidence * 100).toFixed(0)}%</div>
                </div>
              </div>

              <div>
                <InputLabel>{t('ruleRedirectPort')}</InputLabel>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={rule.outcome.targetPort ?? ''}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, targetPort: event.target.value ? Number.parseInt(event.target.value, 10) : undefined } }))}
                  disabled={rule.outcome.actionType !== ActionType.REDIRECT}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none disabled:cursor-not-allowed disabled:opacity-40"
                />
              </div>
            </div>

            <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_auto]">
              <div>
                <InputLabel>{t('ruleExplanation')}</InputLabel>
                <textarea
                  value={rule.outcome.explanation}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, explanation: event.target.value } }))}
                  rows={3}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                />
              </div>

              <label className="flex items-center gap-3 rounded-xl border border-gray-700 bg-[#11161d] px-4 py-3 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={rule.outcome.needsDeepInspection}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, needsDeepInspection: event.target.checked } }))}
                  className="h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500"
                />
                {t('ruleNeedsDeepInspection')}
              </label>
            </div>
          </div>
        </section>
      ))}
    </div>
  );
};

```

## File: `components/Settings.tsx`  
- Path: `components/Settings.tsx`  
- Size: 27916 Bytes  
- Modified: 2026-03-13 14:08:38 UTC

```tsx
import React, { useState } from 'react';
import {
  CaptureInterface,
  Configuration,
  LlmProviderSettings,
  MonitoringStatus,
  ThreatIntelSource,
  WebhookIntegration,
} from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { getProviderDefinition, getSelectedProviderSettings, PROVIDER_DEFINITIONS } from '../services/llmProviders';
import { createId } from '../utils';

interface SettingsProps {
  config: Configuration;
  setConfig: React.Dispatch<React.SetStateAction<Configuration>>;
  availableInterfaces: CaptureInterface[];
  monitoringStatus: MonitoringStatus;
  refreshInterfaces: () => Promise<void>;
  configSyncState: 'idle' | 'saving' | 'saved' | 'error';
  onRefreshThreatIntel: () => Promise<void>;
  threatIntelRefreshPending: boolean;
}

const SectionCard: React.FC<{ title: string; description?: string; children: React.ReactNode }> = ({ title, description, children }) => (
  <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
    <div className="mb-5">
      <h3 className="text-xl font-semibold text-white">{title}</h3>
      {description && <p className="mt-2 text-sm text-gray-400">{description}</p>}
    </div>
    {children}
  </section>
);

const TextInput: React.FC<{ label: string; value: string | number; onChange: (event: React.ChangeEvent<HTMLInputElement>) => void; type?: string; placeholder?: string; disabled?: boolean }> = ({
  label, value, onChange, type = 'text', placeholder, disabled = false,
}) => (
  <div>
    <label className="mb-2 block text-sm font-medium text-gray-400">{label}</label>
    <input
      type={type}
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      disabled={disabled}
      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none disabled:cursor-not-allowed disabled:opacity-40"
    />
  </div>
);

const SelectInput: React.FC<{ label: string; value: string; onChange: (event: React.ChangeEvent<HTMLSelectElement>) => void; children: React.ReactNode }> = ({
  label, value, onChange, children,
}) => (
  <div>
    <label className="mb-2 block text-sm font-medium text-gray-400">{label}</label>
    <select value={value} onChange={onChange} className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none">
      {children}
    </select>
  </div>
);

const ToggleField: React.FC<{ label: string; description: string; checked: boolean; onChange: (checked: boolean) => void }> = ({
  label, description, checked, onChange,
}) => (
  <label className="flex items-start gap-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4">
    <input
      type="checkbox"
      checked={checked}
      onChange={event => onChange(event.target.checked)}
      className="mt-1 h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500"
    />
    <span>
      <span className="block text-sm font-semibold text-white">{label}</span>
      <span className="mt-1 block text-sm text-gray-400">{description}</span>
    </span>
  </label>
);

const SyncBadge: React.FC<{ state: SettingsProps['configSyncState']; label: string }> = ({ state, label }) => {
  const colorClass = state === 'saving'
    ? 'border-yellow-500/30 bg-yellow-500/15 text-yellow-100'
    : state === 'saved'
      ? 'border-emerald-500/30 bg-emerald-500/15 text-emerald-100'
      : state === 'error'
        ? 'border-red-500/30 bg-red-500/15 text-red-100'
        : 'border-gray-600/50 bg-gray-700/50 text-gray-300';

  return <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${colorClass}`}>{label}</span>;
};

export const Settings: React.FC<SettingsProps> = ({
  config,
  setConfig,
  availableInterfaces,
  monitoringStatus,
  refreshInterfaces,
  configSyncState,
  onRefreshThreatIntel,
  threatIntelRefreshPending,
}) => {
  const [ipInput, setIpInput] = useState('');
  const [portInput, setPortInput] = useState('');
  const [exemptPortInput, setExemptPortInput] = useState('');
  const { t } = useLocalization();
  const activeProviderDefinition = getProviderDefinition(config.llmProvider);
  const activeProviderSettings = getSelectedProviderSettings(config);

  const syncStateLabel = configSyncState === 'saving'
    ? t('configSyncSaving')
    : configSyncState === 'saved'
      ? t('configSyncSaved')
      : configSyncState === 'error'
        ? t('configSyncError')
        : t('configSyncIdle');

  const updateProviderSetting = (field: keyof LlmProviderSettings, value: string) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      providerSettings: {
        ...previousConfig.providerSettings,
        [previousConfig.llmProvider]: {
          ...previousConfig.providerSettings[previousConfig.llmProvider],
          [field]: value,
        },
      },
    }));
  };

  const addBlockedIp = () => {
    if (!ipInput || config.blockedIps.includes(ipInput)) {
      return;
    }
    setConfig(previousConfig => ({ ...previousConfig, blockedIps: [...previousConfig.blockedIps, ipInput.trim()] }));
    setIpInput('');
  };

  const addBlockedPort = () => {
    const port = Number.parseInt(portInput, 10);
    if (!port || config.blockedPorts.includes(port)) {
      return;
    }
    setConfig(previousConfig => ({ ...previousConfig, blockedPorts: [...previousConfig.blockedPorts, port] }));
    setPortInput('');
  };

  const addExemptPort = () => {
    const port = Number.parseInt(exemptPortInput, 10);
    if (!port || config.exemptPorts.includes(port)) {
      return;
    }
    setConfig(previousConfig => ({ ...previousConfig, exemptPorts: [...previousConfig.exemptPorts, port] }));
    setExemptPortInput('');
  };

  const addWebhookIntegration = () => {
    const webhook: WebhookIntegration = { id: createId(), name: t('newWebhookName'), provider: 'generic', url: '', enabled: true };
    setConfig(previousConfig => ({ ...previousConfig, webhookIntegrations: [...previousConfig.webhookIntegrations, webhook] }));
  };

  const updateWebhook = <K extends keyof WebhookIntegration,>(integrationId: string, field: K, value: WebhookIntegration[K]) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      webhookIntegrations: previousConfig.webhookIntegrations.map(integration => integration.id === integrationId ? { ...integration, [field]: value } : integration),
    }));
  };

  const addThreatIntelSource = () => {
    const source: ThreatIntelSource = { id: createId(), name: 'New Feed', url: 'https://', format: 'plain', enabled: true };
    setConfig(previousConfig => ({ ...previousConfig, threatIntelSources: [...previousConfig.threatIntelSources, source] }));
  };

  const updateThreatIntelSource = <K extends keyof ThreatIntelSource,>(sourceId: string, field: K, value: ThreatIntelSource[K]) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      threatIntelSources: previousConfig.threatIntelSources.map(source => source.id === sourceId ? { ...source, [field]: value } : source),
    }));
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('settingsTitle')}</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('settingsDescription')}</p>
        </div>
        <SyncBadge state={configSyncState} label={syncStateLabel} />
      </div>

      <div className="grid gap-8 xl:grid-cols-2">
        <SectionCard title={t('settingsFleetConfig')} description={t('settingsFleetDescription')}>
          <div className="grid gap-4 md:grid-cols-2">
            <SelectInput label={t('fleetModeLabel')} value={config.deploymentMode} onChange={event => setConfig(previousConfig => ({ ...previousConfig, deploymentMode: event.target.value as Configuration['deploymentMode'] }))}>
              <option value="standalone">{t('fleetMode_standalone')}</option>
              <option value="hub">{t('fleetMode_hub')}</option>
              <option value="agent">{t('fleetMode_agent')}</option>
            </SelectInput>
            <TextInput label={t('fleetSensorId')} value={config.sensorId} onChange={event => setConfig(previousConfig => ({ ...previousConfig, sensorId: event.target.value }))} />
            <TextInput label={t('fleetSensorName')} value={config.sensorName} onChange={event => setConfig(previousConfig => ({ ...previousConfig, sensorName: event.target.value }))} />
            <TextInput label={t('fleetHubUrl')} value={config.hubUrl} onChange={event => setConfig(previousConfig => ({ ...previousConfig, hubUrl: event.target.value }))} placeholder="http://hub.example.internal:8080" />
            <div className="md:col-span-2">
              <TextInput label={t('fleetSharedToken')} value={config.fleetSharedToken} onChange={event => setConfig(previousConfig => ({ ...previousConfig, fleetSharedToken: event.target.value }))} placeholder={t('fleetSharedTokenPlaceholder')} />
              <p className="mt-2 text-xs text-gray-500">{t('fleetSharedTokenHint')}</p>
            </div>
          </div>
          <div className="mt-5">
            <ToggleField label={t('fleetPropagateBlocks')} description={t('fleetPropagateBlocksHint')} checked={config.globalBlockPropagationEnabled} onChange={checked => setConfig(previousConfig => ({ ...previousConfig, globalBlockPropagationEnabled: checked }))} />
          </div>
        </SectionCard>

        <SectionCard title={t('settingsSensorConfig')} description={t('settingsSensorDescription')}>
          <div className="space-y-4">
            <TextInput label={t('backendBaseUrl')} value={config.backendBaseUrl} onChange={event => setConfig(previousConfig => ({ ...previousConfig, backendBaseUrl: event.target.value }))} placeholder="http://localhost:8081" />
            <div className="flex flex-wrap items-center gap-3 text-sm text-gray-400">
              <span>{monitoringStatus.backendReachable ? t('backendReachable') : t('backendUnreachable')}</span>
              <span>{monitoringStatus.websocketConnected ? t('streamConnected') : t('streamDisconnected')}</span>
              <button onClick={() => void refreshInterfaces()} className="rounded-lg bg-gray-700 px-3 py-2 font-semibold text-white transition hover:bg-gray-600">{t('refreshInterfaces')}</button>
            </div>
            <SelectInput label={t('captureInterface')} value={config.captureInterface} onChange={event => setConfig(previousConfig => ({ ...previousConfig, captureInterface: event.target.value }))}>
              <option value="">{t('autoSelectInterface')}</option>
              {availableInterfaces.map(networkInterface => (
                <option key={networkInterface.name} value={networkInterface.name}>
                  {networkInterface.description} {networkInterface.addresses.length > 0 ? `(${networkInterface.addresses.join(', ')})` : ''}
                </option>
              ))}
            </SelectInput>
            <TextInput label={t('captureFilter')} value={config.captureFilter} onChange={event => setConfig(previousConfig => ({ ...previousConfig, captureFilter: event.target.value }))} placeholder="ip and (tcp or udp)" />
            <p className="text-xs text-gray-500">{t('captureFilterHint')}</p>
            <ToggleField label={t('liveRawFeedEnabled')} description={t('liveRawFeedHint')} checked={config.liveRawFeedEnabled} onChange={checked => setConfig(previousConfig => ({ ...previousConfig, liveRawFeedEnabled: checked }))} />
          </div>
        </SectionCard>
      </div>

      <div className="grid gap-8 xl:grid-cols-2">
        <SectionCard title={t('settingsLlmConfig')} description={t('settingsLlmDescription')}>
          <div className="space-y-4">
            <SelectInput label={t('llmProvider')} value={config.llmProvider} onChange={event => setConfig(previousConfig => ({ ...previousConfig, llmProvider: event.target.value as Configuration['llmProvider'] }))}>
              {PROVIDER_DEFINITIONS.map(provider => (
                <option key={provider.id} value={provider.id}>{provider.label}</option>
              ))}
            </SelectInput>
            <p className="text-xs text-gray-500">{t('llmProviderHint')}</p>
            <TextInput label={t('llmModelId')} value={activeProviderSettings.model} onChange={event => updateProviderSetting('model', event.target.value)} placeholder={activeProviderDefinition.defaultModel} />
            <p className="text-xs text-gray-500">{t('llmModelHint')}</p>
            {activeProviderDefinition.transport !== 'gemini' && (
              <>
                <TextInput label={t('llmBaseUrl')} value={activeProviderSettings.baseUrl} onChange={event => updateProviderSetting('baseUrl', event.target.value)} placeholder={activeProviderDefinition.defaultBaseUrl} />
                <p className="text-xs text-gray-500">{activeProviderDefinition.id === 'lmstudio' ? t('lmStudioUrlHint') : activeProviderDefinition.id === 'ollama' ? t('ollamaUrlHint') : t('providerBaseUrlHint')}</p>
              </>
            )}
            <SelectInput label={t('payloadMaskingMode')} value={config.payloadMaskingMode} onChange={event => setConfig(previousConfig => ({ ...previousConfig, payloadMaskingMode: event.target.value as Configuration['payloadMaskingMode'] }))}>
              <option value="raw_local_only">{t('payloadMaskingMode_raw_local_only')}</option>
              <option value="strict">{t('payloadMaskingMode_strict')}</option>
            </SelectInput>
            <p className="text-xs text-gray-500">{t('payloadMaskingHint')}</p>
            <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-4 text-sm text-blue-100">
              <div className="font-semibold">{t('backendSecretsTitle')}</div>
              <div className="mt-2">{t('backendSecretsHint')}</div>
              {!activeProviderDefinition.local && activeProviderDefinition.envVar && <div className="mt-2 text-blue-200/90">{t('backendSecretsEnvHint', { envVar: activeProviderDefinition.envVar })}</div>}
            </div>
          </div>
        </SectionCard>

        <SectionCard title={t('settingsThreatIntel')} description={t('settingsThreatIntelDescription')}>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-700 bg-gray-900/50 p-4">
              <div className="text-sm text-gray-300">{monitoringStatus.threatIntelStatus.loadedIndicators.toLocaleString()} {t('threatIntelIndicatorsLoaded')}</div>
              <button onClick={() => void onRefreshThreatIntel()} disabled={threatIntelRefreshPending} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-700">{threatIntelRefreshPending ? t('threatIntelRefreshing') : t('threatIntelRefresh')}</button>
            </div>
            <TextInput label={t('threatIntelRefreshHours')} type="number" value={config.threatIntelRefreshHours} onChange={event => setConfig(previousConfig => ({ ...previousConfig, threatIntelRefreshHours: Number.parseInt(event.target.value, 10) || 1 }))} />
            <ToggleField label={t('threatIntelEnabled')} description={t('threatIntelEnabledHint')} checked={config.threatIntelEnabled} onChange={checked => setConfig(previousConfig => ({ ...previousConfig, threatIntelEnabled: checked }))} />
            <ToggleField label={t('threatIntelAutoBlock')} description={t('threatIntelAutoBlockHint')} checked={config.threatIntelAutoBlock} onChange={checked => setConfig(previousConfig => ({ ...previousConfig, threatIntelAutoBlock: checked }))} />
            <div className="flex items-center justify-between pt-2">
              <div className="text-sm text-gray-400">{t('threatIntelSourceCount', { count: config.threatIntelSources.length })}</div>
              <button onClick={addThreatIntelSource} className="rounded-lg bg-gray-700 px-4 py-2 text-sm font-semibold text-white transition hover:bg-gray-600">{t('threatIntelAddSource')}</button>
            </div>
            <div className="space-y-4">
              {config.threatIntelSources.map(source => (
                <div key={source.id} className="rounded-xl border border-gray-700 bg-gray-900/40 p-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <TextInput label={t('threatIntelSourceName')} value={source.name} onChange={event => updateThreatIntelSource(source.id, 'name', event.target.value)} />
                    <SelectInput label={t('threatIntelSourceFormat')} value={source.format} onChange={event => updateThreatIntelSource(source.id, 'format', event.target.value as ThreatIntelSource['format'])}>
                      <option value="spamhaus_drop">Spamhaus DROP</option>
                      <option value="plain">Plain Text / CSV</option>
                      <option value="json_array">JSON Array</option>
                    </SelectInput>
                  </div>
                  <div className="mt-4">
                    <TextInput label={t('threatIntelSourceUrl')} value={source.url} onChange={event => updateThreatIntelSource(source.id, 'url', event.target.value)} />
                  </div>
                  <div className="mt-4 flex items-center justify-between">
                    <label className="flex items-center gap-3 text-sm text-gray-300">
                      <input type="checkbox" checked={source.enabled} onChange={event => updateThreatIntelSource(source.id, 'enabled', event.target.checked)} className="h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500" />
                      {t('webhookEnabled')}
                    </label>
                    <button onClick={() => setConfig(previousConfig => ({ ...previousConfig, threatIntelSources: previousConfig.threatIntelSources.filter(item => item.id !== source.id) }))} className="text-sm font-semibold text-red-300 transition hover:text-red-200">{t('remove')}</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>
      </div>

      <div className="grid gap-8 xl:grid-cols-2">
        <SectionCard title={t('settingsAnalysisPipeline')} description={t('settingsAnalysisDescription')}>
          <div className="grid gap-4 md:grid-cols-2">
            <TextInput label={t('cacheTtlSeconds')} type="number" value={config.cacheTtlSeconds} onChange={event => setConfig(previousConfig => ({ ...previousConfig, cacheTtlSeconds: Number.parseInt(event.target.value, 10) || 1 }))} />
            <TextInput label={t('batchWindowMs')} type="number" value={config.batchWindowMs} onChange={event => setConfig(previousConfig => ({ ...previousConfig, batchWindowMs: Number.parseInt(event.target.value, 10) || 100 }))} />
            <TextInput label={t('batchMaxSize')} type="number" value={config.batchMaxSize} onChange={event => setConfig(previousConfig => ({ ...previousConfig, batchMaxSize: Number.parseInt(event.target.value, 10) || 1 }))} />
            <TextInput label={t('secureRedirectPort')} type="number" value={config.securePort} onChange={event => setConfig(previousConfig => ({ ...previousConfig, securePort: Number.parseInt(event.target.value, 10) || 1 }))} />
            <TextInput label={t('pcapBufferSize')} type="number" value={config.pcapBufferSize} onChange={event => setConfig(previousConfig => ({ ...previousConfig, pcapBufferSize: Number.parseInt(event.target.value, 10) || 1 }))} />
            <div className="md:col-span-2">
              <label className="mb-2 block text-sm font-medium text-gray-400">{t('monitoringPorts')}</label>
              <input
                type="text"
                value={config.monitoringPorts.join(', ')}
                onChange={event => setConfig(previousConfig => ({
                  ...previousConfig,
                  monitoringPorts: event.target.value.split(',').map(port => Number.parseInt(port.trim(), 10)).filter(port => !Number.isNaN(port)),
                }))}
                className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div className="md:col-span-2">
              <label className="mb-2 block text-sm font-medium text-gray-400">
                {t('detectionThreshold')}: <span className="text-blue-300">{(config.detectionThreshold * 100).toFixed(0)}%</span>
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={config.detectionThreshold}
                onChange={event => setConfig(previousConfig => ({ ...previousConfig, detectionThreshold: Number.parseFloat(event.target.value) }))}
                className="w-full"
              />
              <p className="mt-2 text-xs text-gray-500">{t('detectionThresholdHint')}</p>
            </div>
          </div>
          <div className="mt-5 space-y-4">
            <ToggleField label={t('autoBlockThreats')} description={t('autoBlockThreatsHint')} checked={config.autoBlockThreats} onChange={checked => setConfig(previousConfig => ({ ...previousConfig, autoBlockThreats: checked }))} />
            <ToggleField label={t('firewallIntegrationEnabled')} description={t('firewallIntegrationHint')} checked={config.firewallIntegrationEnabled} onChange={checked => setConfig(previousConfig => ({ ...previousConfig, firewallIntegrationEnabled: checked }))} />
          </div>
        </SectionCard>

        <SectionCard title={t('settingsIntegrations')} description={t('webhookHint')}>
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">{t('webhookSummary', { count: config.webhookIntegrations.length })}</div>
            <button onClick={addWebhookIntegration} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700">{t('addWebhook')}</button>
          </div>
          <div className="mt-4 space-y-4">
            {config.webhookIntegrations.length === 0 && <div className="rounded-xl border border-dashed border-gray-700 p-6 text-center text-sm text-gray-500">{t('noWebhooksConfigured')}</div>}
            {config.webhookIntegrations.map(integration => (
              <div key={integration.id} className="rounded-xl border border-gray-700 bg-gray-900/40 p-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <TextInput label={t('webhookName')} value={integration.name} onChange={event => updateWebhook(integration.id, 'name', event.target.value)} />
                  <SelectInput label={t('webhookProvider')} value={integration.provider} onChange={event => updateWebhook(integration.id, 'provider', event.target.value as WebhookIntegration['provider'])}>
                    <option value="generic">{t('webhookProviderGeneric')}</option>
                    <option value="slack">Slack</option>
                    <option value="discord">Discord</option>
                    <option value="teams">Teams</option>
                  </SelectInput>
                </div>
                <div className="mt-4">
                  <TextInput label={t('webhookUrl')} value={integration.url} onChange={event => updateWebhook(integration.id, 'url', event.target.value)} placeholder="https://..." />
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <label className="flex items-center gap-3 text-sm text-gray-300">
                    <input type="checkbox" checked={integration.enabled} onChange={event => updateWebhook(integration.id, 'enabled', event.target.checked)} className="h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500" />
                    {t('webhookEnabled')}
                  </label>
                  <button onClick={() => setConfig(previousConfig => ({ ...previousConfig, webhookIntegrations: previousConfig.webhookIntegrations.filter(item => item.id !== integration.id) }))} className="text-sm font-semibold text-red-300 transition hover:text-red-200">{t('remove')}</button>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>

      <div className="grid gap-8 md:grid-cols-2 xl:grid-cols-3">
        <SectionCard title={t('blockedIpAddresses')}>
          <div className="mb-4 flex gap-2">
            <input type="text" value={ipInput} onChange={event => setIpInput(event.target.value)} placeholder={t('enterIpAddress')} className="flex-1 rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none" />
            <button onClick={addBlockedIp} className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700">{t('add')}</button>
          </div>
          <ul className="space-y-2">
            {config.blockedIps.map(ip => (
              <li key={ip} className="flex items-center justify-between rounded-lg bg-gray-900/60 px-3 py-2">
                <span className="font-mono text-cyan-300">{ip}</span>
                <button onClick={() => setConfig(previousConfig => ({ ...previousConfig, blockedIps: previousConfig.blockedIps.filter(item => item !== ip) }))} className="text-sm font-semibold text-red-300">{t('remove')}</button>
              </li>
            ))}
          </ul>
        </SectionCard>

        <SectionCard title={t('blockedPorts')}>
          <div className="mb-4 flex gap-2">
            <input type="number" value={portInput} onChange={event => setPortInput(event.target.value)} placeholder={t('enterPortNumber')} className="flex-1 rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none" />
            <button onClick={addBlockedPort} className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700">{t('add')}</button>
          </div>
          <ul className="space-y-2">
            {config.blockedPorts.map(port => (
              <li key={port} className="flex items-center justify-between rounded-lg bg-gray-900/60 px-3 py-2">
                <span className="font-mono text-purple-300">{port}</span>
                <button onClick={() => setConfig(previousConfig => ({ ...previousConfig, blockedPorts: previousConfig.blockedPorts.filter(item => item !== port) }))} className="text-sm font-semibold text-red-300">{t('remove')}</button>
              </li>
            ))}
          </ul>
        </SectionCard>

        <SectionCard title={t('settingsExemptPorts')}>
          <div className="mb-4 flex gap-2">
            <input type="number" value={exemptPortInput} onChange={event => setExemptPortInput(event.target.value)} placeholder={t('enterPortNumber')} className="flex-1 rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none" />
            <button onClick={addExemptPort} className="rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700">{t('add')}</button>
          </div>
          <ul className="space-y-2">
            {config.exemptPorts.map(port => (
              <li key={port} className="flex items-center justify-between rounded-lg bg-gray-900/60 px-3 py-2">
                <span className="font-mono text-purple-300">{port}</span>
                <button onClick={() => setConfig(previousConfig => ({ ...previousConfig, exemptPorts: previousConfig.exemptPorts.filter(item => item !== port) }))} className="text-sm font-semibold text-red-300">{t('remove')}</button>
              </li>
            ))}
          </ul>
        </SectionCard>
      </div>
    </div>
  );
};

```

## File: `components/Sidebar.tsx`  
- Path: `components/Sidebar.tsx`  
- Size: 3864 Bytes  
- Modified: 2026-03-13 13:08:38 UTC

```tsx
import React from 'react';
import { useLocalization } from '../hooks/useLocalization';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: 'Dashboard' | 'Rules' | 'Settings' | 'Logs' | 'Fleet' | 'ThreatHunt') => void;
}

const NavLogo: React.FC = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10 text-blue-500" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5L12 1Z" />
    <path className="text-[#0D1117]" d="M12 3.17L4 6.3v4.7c0 4.1 2.93 8.23 8 9.4 5.07-1.17 8-5.3 8-9.4V6.3L12 3.17z" />
    <g stroke="white" strokeWidth={1.2} strokeLinecap="round" transform="translate(4 4) scale(0.66)">
      <circle cx="12" cy="12" r="3" />
      <path d="M12 6V3m0 18v-3m6-6h3M3 12h3m7.5-7.5L21 3M3 21l1.5-1.5M21 21l-1.5-1.5M3 3l1.5 1.5" />
    </g>
  </svg>
);

const NavItem = ({ icon, label, isActive, onClick }: { icon: React.ReactNode; label: string; isActive: boolean; onClick: () => void }) => (
  <button
    onClick={onClick}
    className={`flex w-full items-center space-x-3 rounded-lg px-4 py-3 transition-colors duration-200 ${
      isActive ? 'bg-blue-500/20 text-white' : 'text-gray-400 hover:bg-gray-700/50 hover:text-white'
    }`}
  >
    {icon}
    <span className="font-semibold">{label}</span>
  </button>
);

const icon = (path: string) => (
  <svg className="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d={path} />
  </svg>
);

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const { t } = useLocalization();

  const navItems = [
    { id: 'Dashboard' as const, label: t('dashboardTab'), icon: icon('M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6') },
    { id: 'Fleet' as const, label: t('fleetTab'), icon: icon('M17 20h5V4H2v16h5m10 0v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6m10 0H7') },
    { id: 'ThreatHunt' as const, label: t('threatHuntTab'), icon: icon('M8 16l4-4 4 4m0-8l-4 4-4-4') },
    { id: 'Rules' as const, label: t('rulesTab'), icon: icon('M9 5h10M9 9h10M9 13h10M9 17h10M4 5h.01M4 9h.01M4 13h.01M4 17h.01') },
    { id: 'Settings' as const, label: t('settingsTab'), icon: icon('M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.096 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z') },
    { id: 'Logs' as const, label: t('logsTab'), icon: icon('M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z') },
  ];

  return (
    <aside className="hidden w-64 flex-col border-r border-gray-700/50 bg-[#161B22] p-4 md:flex">
      <div className="mb-6 flex items-center space-x-3 p-4">
        <NavLogo />
        <h1 className="text-2xl font-bold tracking-wide text-white">NetGuard <span className="text-blue-400">AI</span></h1>
      </div>
      <nav className="flex-1 space-y-2">
        {navItems.map(item => (
          <NavItem
            key={item.id}
            label={item.label}
            icon={item.icon}
            isActive={activeTab === item.id}
            onClick={() => setActiveTab(item.id)}
          />
        ))}
      </nav>
      <div className="p-4 text-center text-xs text-gray-600">
        &copy; {new Date().getFullYear()} NetGuard AI
      </div>
    </aside>
  );
};

```

## File: `components/StatCard.tsx`  
- Path: `components/StatCard.tsx`  
- Size: 697 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```tsx
import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  description: string;
  valueColor?: string;
  children?: React.ReactNode;
}

export const StatCard: React.FC<StatCardProps> = ({ title, value, description, valueColor = 'text-white', children }) => {
  return (
    <div className="bg-[#161B22] p-5 rounded-lg shadow-lg border border-gray-700/50 flex flex-col justify-between">
      <div>
        <p className="text-sm font-medium text-gray-400">{title}</p>
        <p className={`text-3xl font-bold mt-2 ${valueColor}`}>{value}</p>
      </div>
      <p className="text-xs text-gray-500 mt-3">{description}</p>
      {children}
    </div>
  );
};

```

## File: `components/ThreatHunter.tsx`  
- Path: `components/ThreatHunter.tsx`  
- Size: 5337 Bytes  
- Modified: 2026-03-13 13:08:14 UTC

```tsx
import React, { useState } from 'react';
import { SensorSummary, ThreatHuntingResponse } from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { runThreatHunt } from '../services/backendService';

interface ThreatHunterProps {
  backendBaseUrl: string;
  selectedSensorId: string | null;
  sensors: SensorSummary[];
}

export const ThreatHunter: React.FC<ThreatHunterProps> = ({
  backendBaseUrl,
  selectedSensorId,
  sensors,
}) => {
  const { t } = useLocalization();
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<ThreatHuntingResponse | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!question.trim()) {
      return;
    }

    setPending(true);
    setError(null);

    try {
      const response = await runThreatHunt(backendBaseUrl, question.trim(), selectedSensorId);
      setResult(response.result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : t('unknownError'));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white">{t('threatHuntTitle')}</h2>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('threatHuntDescription')}</p>
      </div>

      <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
        <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
          <div className="space-y-3">
            <label className="block text-sm font-medium text-gray-400">{t('threatHuntPrompt')}</label>
            <textarea
              value={question}
              onChange={event => setQuestion(event.target.value)}
              rows={4}
              className="w-full rounded-xl border border-gray-600 bg-gray-900 px-4 py-3 text-white focus:border-blue-500 focus:outline-none"
              placeholder={t('threatHuntPlaceholder')}
            />
            <div className="text-sm text-gray-500">
              {selectedSensorId
                ? t('threatHuntScopedSensor', { sensorName: sensors.find(sensor => sensor.id === selectedSensorId)?.name || selectedSensorId })
                : t('threatHuntScopedGlobal')}
            </div>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => void handleSubmit()}
              disabled={pending || !question.trim()}
              className="rounded-xl bg-blue-600 px-5 py-3 font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-700"
            >
              {pending ? t('threatHuntRunning') : t('threatHuntRun')}
            </button>
          </div>
        </div>
        {error && <div className="mt-4 text-sm text-red-300">{error}</div>}
      </section>

      {result && (
        <>
          <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
            <h3 className="text-xl font-semibold text-white">{t('threatHuntSummary')}</h3>
            <p className="mt-3 text-sm leading-6 text-gray-300">{result.summary}</p>
          </section>

          <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
            <h3 className="text-xl font-semibold text-white">{t('threatHuntSql')}</h3>
            <pre className="mt-4 overflow-x-auto rounded-xl bg-gray-900 p-4 text-xs text-green-300">{result.sql}</pre>
          </section>

          <section className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
            <div className="border-b border-gray-700/50 p-4">
              <h3 className="text-xl font-semibold text-white">{t('threatHuntResults')}</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-800/30">
                  <tr>
                    {(Object.keys(result.rows[0] ?? {}) || ['empty']).map(column => (
                      <th key={column} className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                        {column}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {result.rows.length === 0 && (
                    <tr>
                      <td className="p-8 text-center text-gray-500">{t('threatHuntNoRows')}</td>
                    </tr>
                  )}
                  {result.rows.map((row, index) => (
                    <tr key={`${result.id}-${index}`} className="bg-[#161B22] text-sm hover:bg-[#1a212c]">
                      {Object.entries(row).map(([column, value]) => (
                        <td key={column} className="p-3 align-top text-gray-300">
                          <span className="break-all">{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '')}</span>
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
};

```

## File: `context/LocalizationContext.tsx`  
- Path: `context/LocalizationContext.tsx`  
- Size: 2483 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```tsx
import React, { createContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { translations } from '../locales/translations';

export type Language = keyof typeof translations;

export const languages: { [key in Language]: string } = {
    en: 'English',
    de: 'Deutsch',
    es: 'Español',
    fr: 'Français',
    it: 'Italiano',
    ja: '日本語',
    nl: 'Nederlands',
    ru: 'Русский',
    zh: '中文',
    ar: 'العربية'
};

interface LocalizationContextType {
    t: (key: string, replacements?: { [key: string]: string | number }) => string;
    changeLanguage: (lang: Language) => void;
    currentLanguage: Language;
    languages: { [key in Language]: string };
}

export const LocalizationContext = createContext<LocalizationContextType | undefined>(undefined);

interface LocalizationProviderProps {
    children: ReactNode;
}

export const LocalizationProvider: React.FC<LocalizationProviderProps> = ({ children }) => {
    const getInitialLanguage = (): Language => {
        const savedLang = localStorage.getItem('language') as Language;
        if (savedLang && languages[savedLang]) {
            return savedLang;
        }
        const browserLang = navigator.language.split('-')[0] as Language;
        return languages[browserLang] ? browserLang : 'en';
    };

    const [currentLanguage, setCurrentLanguage] = useState<Language>(getInitialLanguage);

    useEffect(() => {
        localStorage.setItem('language', currentLanguage);
        document.documentElement.lang = currentLanguage;
        document.documentElement.dir = currentLanguage === 'ar' ? 'rtl' : 'ltr';
    }, [currentLanguage]);

    const changeLanguage = (lang: Language) => {
        if (languages[lang]) {
            setCurrentLanguage(lang);
        }
    };

    const t = useCallback((key: string, replacements: { [key: string]: string | number } = {}): string => {
        let translation = translations[currentLanguage]?.[key] || translations['en'][key] || key;
        
        Object.keys(replacements).forEach(placeholder => {
            const regex = new RegExp(`\\{${placeholder}\\}`, 'g');
            translation = translation.replace(regex, String(replacements[placeholder]));
        });

        return translation;
    }, [currentLanguage]);

    return (
        <LocalizationContext.Provider value={{ t, changeLanguage, currentLanguage, languages }}>
            {children}
        </LocalizationContext.Provider>
    );
};

```

## File: `data/netguard.db`  
- Path: `data/netguard.db`  
- Size: 2043904 Bytes  
- Modified: 2026-03-13 14:34:46 UTC

> **Skipped**: File is larger than max size (2000000 bytes).

## File: `data/netguard.db-shm`  
- Path: `data/netguard.db-shm`  
- Size: 32768 Bytes  
- Modified: 2026-03-13 14:31:56 UTC

> **Binary file skipped** (mode: skip).

## File: `data/netguard.db-wal`  
- Path: `data/netguard.db-wal`  
- Size: 4140632 Bytes  
- Modified: 2026-03-13 14:34:54 UTC

> **Skipped**: File is larger than max size (2000000 bytes).

## File: `hooks/useLocalization.ts`  
- Path: `hooks/useLocalization.ts`  
- Size: 414 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```typescript

import { useContext } from 'react';
import { LocalizationContext } from '../context/LocalizationContext';

export const useLocalization = () => {
    const context = useContext(LocalizationContext);
    if (context === undefined) {
        throw new Error('useLocalization must be used within a LocalizationProvider');
    }
    return context;
};

export type { Language } from '../context/LocalizationContext';

```

## File: `index.html`  
- Path: `index.html`  
- Size: 772 Bytes  
- Modified: 2026-03-13 11:23:34 UTC

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>NetGuard AI</title>
    <script src="https://cdn.tailwindcss.com"></script>

    <script type="importmap">
    {
      "imports": {
        "react":             "https://esm.sh/react@^19.1.0",
        "react/":            "https://esm.sh/react@^19.1.0/",
        "react-dom/":        "https://esm.sh/react-dom@^19.1.0/",
        "@google/genai":     "https://esm.sh/@google/genai@^1.9.0"
      }
    }
    </script>
</head>
  <body class="bg-[#0D1117]">
    <div id="root"></div>
    <script type="module" src="/index.tsx"></script>
  </body>
</html>

```

## File: `index.tsx`  
- Path: `index.tsx`  
- Size: 477 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```tsx

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { LocalizationProvider } from './context/LocalizationContext';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <LocalizationProvider>
      <App />
    </LocalizationProvider>
  </React.StrictMode>
);
```

## File: `locales/translations.ts`  
- Path: `locales/translations.ts`  
- Size: 25450 Bytes  
- Modified: 2026-03-13 14:23:48 UTC

```typescript
const en = {
  headerTitle: 'NetGuard AI',
  localeCode: 'en-US',
  dashboardTitle: 'Operational Network Defense',
  dashboardDescription: 'The backend sensor now performs packet capture, heuristic filtering, LLM escalation, persistence, firewall actions and PCAP forensics without relying on the browser.',

  monitoringStatusCardTitle: 'Monitoring Status',
  backendStatusCardTitle: 'Backend Sensor',
  llmStatusCardTitle: 'LLM Pipeline',
  packetsProcessedCardTitle: 'Packets Processed',
  threatsDetectedCardTitle: 'Threats Detected',
  blockedDecisionsCardTitle: 'Blocked Decisions',

  activeStatus: 'Active',
  stoppedStatus: 'Stopped',
  connectedStatus: 'Connected',
  disconnectedStatus: 'Disconnected',
  loadedStatus: 'Ready',
  errorStatus: 'Unavailable',
  startingStatus: 'Starting...',
  stoppingStatus: 'Stopping...',
  persistedHistoryBackend: 'Persisted in backend storage',
  lifetimeCounter: 'Lifetime counter',
  last24Hours: 'Last 24 hours',
  streamConnected: 'WebSocket stream connected',
  streamDisconnected: 'WebSocket stream disconnected',
  captureDeviceLabel: 'Device',
  captureIdle: 'Capture inactive',
  captureFilterLabel: 'Capture Filter',
  captureFilterUnset: 'No capture filter configured',
  firewallApplied: 'Firewall applied',

  startMonitoringButton: 'Start Monitoring',
  stopMonitoringButton: 'Stop Monitoring',

  dashboardTab: 'Dashboard',
  fleetTab: 'Fleet',
  threatHuntTab: 'Threat Hunt',
  rulesTab: 'Rules',
  settingsTab: 'Settings',
  logsTab: 'Logs',

  replayStatusLabel: 'Replay',
  replayState_idle: 'Idle',
  replayState_running: 'Running',
  replayState_completed: 'Completed',
  replayState_failed: 'Failed',

  liveTrafficFeed: 'Analyzed Traffic Feed',
  startMonitoringToSeeTraffic: 'Start monitoring to see analyzed traffic.',
  waitingForTraffic: 'Monitoring active, waiting for traffic.',
  noThreatsDetected: 'No threats detected yet.',

  replayTitle: 'Historical Replay',
  replayDescription: 'Upload a PCAP file and replay it through the same backend analysis pipeline used for live monitoring.',
  pcapFileLabel: 'PCAP File',
  replaySpeedLabel: 'Replay Speed',
  replayRunning: 'Replay running...',
  startReplayButton: 'Start Replay',
  replayHint: 'Replay is disabled while live capture is active. Increase the speed multiplier to accelerate historical analysis.',

  forensicsTitle: 'PCAP Forensics',
  forensicsDescription: 'Threat windows are exported on the backend and kept available for download and offline analysis in Wireshark.',
  noArtifactsYet: 'No PCAP artifacts available yet.',
  packetsLabel: 'packets',
  downloadPcap: 'Download PCAP',

  rawFeedTitle: 'Live Raw Feed',
  rawFeedDescription: 'Optional raw packet mirror from the backend sensor. This is intended for troubleshooting and protocol verification.',
  rawFeedSource: 'Source',
  rawFeedDestination: 'Destination',
  rawFeedL7: 'L7',
  rawFeedMetadata: 'Metadata',
  rawFeedEmpty: 'Enable raw feed mode and start capture to inspect decoded packets.',

  colTimestamp: 'Timestamp',
  colSourceIp: 'Source IP',
  colDestPort: 'Dest Port',
  colProtocol: 'Protocol',
  colAttackType: 'Attack Type',
  colConfidence: 'Confidence',
  colProcess: 'Local Process',
  colAction: 'Action',
  colDecisionSource: 'Decision Source',
  colLlmExplanation: 'Explanation',
  processFilterLabel: 'Process Filter',
  processFilterPlaceholder: 'Filter by process name, PID, path, signer or service...',
  processFilterClear: 'Clear',
  processFilterButton: 'Filter like this',
  processCopyPath: 'Copy Path',
  processOpenFolder: 'Open Folder',
  processCompany: 'Binary',
  processSignature: 'Signature',
  processServices: 'Services',
  processActionCopied: 'Process path copied to clipboard.',
  processActionOpened: 'Process location opened in Explorer.',
  processActionFailed: 'Process action failed.',
  processNoFilterMatches: 'No traffic rows match the current process filter.',
  processUnavailable: 'Not resolved',
  processUnknown: 'Unknown process',
  processPathUnavailable: 'Path unavailable',
  processLocalPort: 'Local port',
  colLevel: 'Level',
  colMessage: 'Message',
  colDetails: 'Details',

  settingsTitle: 'Settings',
  settingsDescription: 'Backend configuration is managed centrally. Changes here are synced to the service and persisted server-side.',
  settingsFleetConfig: 'Fleet & Deployment',
  settingsFleetDescription: 'Configure whether this node runs standalone, as a central hub, or as a remote agent connected to a hub.',
  settingsSensorConfig: 'Sensor & Backend',
  settingsSensorDescription: 'Control backend reachability, interface selection and raw feed behavior.',
  settingsLlmConfig: 'LLM Configuration',
  settingsLlmDescription: 'The backend owns all API secrets. The browser edits only provider routing, model selection and local endpoints.',
  settingsThreatIntel: 'Threat Intelligence',
  settingsThreatIntelDescription: 'Load external IP/CIDR feeds into the backend and short-circuit known malicious sources before heuristics or LLM analysis.',
  settingsAnalysisPipeline: 'Analysis Pipeline',
  settingsAnalysisDescription: 'Tune cache windows, batching, thresholds, redirect behavior and PCAP retention.',
  settingsIntegrations: 'Integrations',
  settingsExemptPorts: 'Exempt Ports',

  fleetTitle: 'Fleet Management',
  fleetDescription: 'Manage distributed sensors from one dashboard and scope analytics to a single sensor or the entire fleet.',
  fleetModeLabel: 'Deployment Mode',
  fleetMode_standalone: 'Standalone',
  fleetMode_hub: 'Central Hub',
  fleetMode_agent: 'Remote Agent',
  fleetSensorId: 'Sensor ID',
  fleetSensorName: 'Sensor Name',
  fleetHubUrl: 'Hub URL',
  fleetSharedToken: 'Shared Fleet Token',
  fleetSharedTokenPlaceholder: 'Leave empty to keep current server token',
  fleetSharedTokenHint: 'Use the same token on the hub and all agents to authenticate the fleet WebSocket channel.',
  fleetPropagateBlocks: 'Propagate global blocks',
  fleetPropagateBlocksHint: 'Push newly blocked IP addresses to connected agents so the whole fleet can enforce them.',
  fleetStatusLabel: 'Fleet Status',
  fleetConnectedHub: 'Connected to hub',
  fleetStandaloneHint: 'No upstream hub connection active',
  fleetNoHubConfigured: 'No hub URL configured',
  fleetSensorsConnected: 'Connected Sensors',
  fleetAllSensors: 'All Sensors',
  fleetSensorsTable: 'Registered Sensors',
  fleetColSensor: 'Sensor',
  fleetColMode: 'Mode',
  fleetColStatus: 'Status',
  fleetColCapture: 'Capture',
  fleetColLastSeen: 'Last Seen',
  fleetNoSensors: 'No fleet sensors available yet.',

  sensorScopeLabel: 'Sensor Scope',
  sensorScopeSelected: 'Scoped to sensor: {sensorName}',
  sensorScopeGlobal: 'Global analytics view across all sensors',

  llmProvider: 'LLM Provider',
  llmProviderHint: 'Select the provider or local runtime used for deep inspection on the backend.',
  llmModelId: 'Model ID',
  llmModelHint: 'Use the exact model ID expected by the selected provider.',
  llmBaseUrl: 'Base URL',
  providerBaseUrlHint: 'Change this only if you use a custom endpoint or proxy.',
  lmStudioUrlHint: 'Example: http://localhost:1234/v1',
  ollamaUrlHint: 'Example: http://localhost:11434',
  backendSecretsTitle: 'Backend-managed secrets',
  backendSecretsHint: 'API keys are never returned to the browser. Configure them on the server via environment variables or a secured service wrapper.',
  backendSecretsEnvHint: 'Expected environment variable: {envVar}',
  payloadMaskingMode: 'Payload Privacy Mode',
  payloadMaskingMode_raw_local_only: 'Raw payload for local LLMs only',
  payloadMaskingMode_strict: 'Strict masking for all providers',
  payloadMaskingHint: 'Cloud providers are scrubbed automatically. Strict mode also masks payloads before they reach local runtimes.',

  backendBaseUrl: 'Backend Base URL',
  backendReachable: 'Backend reachable',
  backendUnreachable: 'Backend unreachable',
  refreshInterfaces: 'Refresh Interfaces',
  captureInterface: 'Capture Interface',
  autoSelectInterface: 'Auto-select best active interface',
  captureFilter: 'Capture Filter',
  captureFilterHint: 'Uses libpcap syntax, for example: ip and (tcp or udp).',
  liveRawFeedEnabled: 'Enable live raw feed',
  liveRawFeedHint: 'Broadcast decoded raw packets over WebSocket in addition to analyzed events.',

  cacheTtlSeconds: 'Cache TTL (seconds)',
  batchWindowMs: 'Batch Window (ms)',
  batchMaxSize: 'Batch Size',
  secureRedirectPort: 'Secure Redirect Port',
  pcapBufferSize: 'PCAP Buffer Size',
  monitoringPorts: 'Monitoring Ports (comma-separated)',
  detectionThreshold: 'Detection Threshold',
  detectionThresholdHint: 'Confidence level required before the backend applies automatic blocking or redirect decisions.',
  autoBlockThreats: 'Auto-block detected threats',
  autoBlockThreatsHint: 'When enabled, suspicious source IPs are added to the persistent backend blocklist.',
  firewallIntegrationEnabled: 'Enable OS firewall integration',
  firewallIntegrationHint: 'Execute real system firewall commands when the backend decides to block a source IP.',

  threatIntelStatusLabel: 'Threat Intel',
  threatIntelIndicatorsLoaded: 'indicators loaded',
  threatIntelRefresh: 'Refresh Feeds',
  threatIntelRefreshing: 'Refreshing...',
  threatIntelRefreshHours: 'Refresh Interval (hours)',
  threatIntelEnabled: 'Enable threat intelligence',
  threatIntelEnabledHint: 'Fetch configured threat feeds and check source IPs before heuristics and LLM escalation.',
  threatIntelAutoBlock: 'Auto-block threat intel matches',
  threatIntelAutoBlockHint: 'Immediately block packets whose source IP matches a loaded threat intelligence indicator.',
  threatIntelSourceCount: '{count} feed sources configured',
  threatIntelAddSource: 'Add Feed',
  threatIntelSourceName: 'Feed Name',
  threatIntelSourceFormat: 'Feed Format',
  threatIntelSourceUrl: 'Feed URL',

  webhookHint: 'Outgoing alerts are sent by the backend service to avoid browser CORS limitations and keep integrations running in headless mode.',
  webhookSummary: '{count} webhook integrations configured',
  addWebhook: 'Add Webhook',
  noWebhooksConfigured: 'No webhooks configured.',
  webhookName: 'Webhook Name',
  webhookProvider: 'Webhook Type',
  webhookProviderGeneric: 'Generic JSON',
  webhookUrl: 'Webhook URL',
  webhookEnabled: 'Enabled',
  newWebhookName: 'New webhook',

  blockedIpAddresses: 'Blocked IP Addresses',
  enterIpAddress: 'Enter IP address...',
  blockedPorts: 'Blocked Ports',
  enterPortNumber: 'Enter port number...',
  add: 'Add',
  remove: 'Remove',

  rulesTitle: 'Custom Rule Builder',
  rulesDescription: 'Build IF/THEN rules that run before the built-in heuristics and before any LLM escalation. Matching rules can allow, block or redirect traffic immediately.',
  addRule: 'Add Rule',
  rulesEmptyState: 'No custom rules configured yet.',
  newCustomRuleName: 'New custom rule',
  newCustomRuleExplanation: 'Custom security policy matched this traffic.',
  ruleName: 'Rule Name',
  ruleMatchMode: 'Match Mode',
  ruleMatchModeAll: 'All conditions',
  ruleMatchModeAny: 'Any condition',
  ruleEnabled: 'Enabled',
  removeRule: 'Remove Rule',
  ruleConditions: 'Conditions',
  ruleConditionsHint: 'Conditions are evaluated against decoded packet fields and Layer 7 metadata.',
  addCondition: 'Add Condition',
  ruleField: 'Field',
  ruleValue: 'Value',
  ruleOperator: 'Operator',
  ruleOutcome: 'Outcome',
  ruleOutcomeHint: 'Define the resulting action, attack type, confidence and whether the traffic should still go through deep inspection.',
  ruleAction: 'Action',
  ruleAction_allow: 'Allow',
  ruleAction_block: 'Block',
  ruleAction_redirect: 'Redirect',
  ruleAttackType: 'Attack Type',
  ruleConfidence: 'Confidence',
  ruleRedirectPort: 'Redirect Port',
  ruleExplanation: 'Explanation',
  ruleNeedsDeepInspection: 'Still send matching traffic to deep inspection',

  ruleField_sourceIp: 'Source IP',
  ruleField_destinationIp: 'Destination IP',
  ruleField_sourcePort: 'Source Port',
  ruleField_destinationPort: 'Destination Port',
  ruleField_protocol: 'Transport Protocol',
  ruleField_direction: 'Direction',
  ruleField_size: 'Packet Size',
  ruleField_l7Protocol: 'Layer 7 Protocol',
  ruleField_payloadSnippet: 'Payload Snippet',
  'ruleField_l7.host': 'HTTP Host',
  'ruleField_l7.path': 'HTTP Path',
  'ruleField_l7.userAgent': 'HTTP User-Agent',
  'ruleField_l7.dnsQuery': 'DNS Query',
  'ruleField_l7.sni': 'TLS SNI',

  ruleOperator_equals: 'Equals',
  ruleOperator_not_equals: 'Not equals',
  ruleOperator_greater_than: 'Greater than',
  ruleOperator_less_than: 'Less than',
  ruleOperator_contains: 'Contains',
  ruleOperator_starts_with: 'Starts with',
  ruleOperator_in_cidr: 'In CIDR',
  ruleOperator_not_in_cidr: 'Not in CIDR',
  ruleOperator_in_list: 'In list',
  ruleOperator_not_in_list: 'Not in list',

  attackType_port_scan: 'Port Scan',
  attackType_brute_force: 'Brute Force',
  attackType_malicious_payload: 'Malicious Payload',
  attackType_ddos: 'DDoS',
  attackType_none: 'None',
  attackType_other: 'Other',

  trafficTrendTitle: 'Traffic vs. Threats',
  trafficTrendDescription: 'Persistent telemetry from backend storage over the last 24 hours.',
  trafficCountSeries: 'Traffic',
  threatCountSeries: 'Threats',
  blockedCountSeries: 'Blocked',

  threatHuntTitle: 'Interactive Threat Hunting',
  threatHuntDescription: 'Ask natural-language questions against the backend forensics database. The backend translates them into read-only SQL and summarizes the result set.',
  threatHuntPrompt: 'Threat hunting question',
  threatHuntPlaceholder: 'Show me all source IPs that attempted SSH connections yesterday and were classified as brute_force.',
  threatHuntScopedSensor: 'The next hunt is scoped to sensor: {sensorName}',
  threatHuntScopedGlobal: 'The next hunt runs across all sensors.',
  threatHuntRun: 'Run Hunt',
  threatHuntRunning: 'Running...',
  threatHuntSummary: 'Summary',
  threatHuntSql: 'Generated SQL',
  threatHuntResults: 'Result Rows',
  threatHuntNoRows: 'No rows matched this query.',

  logsTitle: 'Event Logs',
  logsDescription: 'Review backend and fleet events with sensor-aware filtering.',
  noLogsYet: 'No logs yet. Start monitoring to generate events.',

  configSyncIdle: 'Synchronized',
  configSyncSaving: 'Saving...',
  configSyncSaved: 'Saved',
  configSyncError: 'Sync failed',

  logBootstrapFailed: 'Failed to load backend bootstrap payload.',
  logCaptureError: 'Packet capture error',
  logPacketDecodeFailed: 'Failed to decode backend WebSocket message.',
  logWebSocketError: 'Traffic WebSocket error',
  logInterfacesRefreshFailed: 'Failed to refresh capture interfaces.',
  logMonitoringStartFailed: 'Failed to start network monitoring.',
  logMonitoringStopFailed: 'Failed to stop network monitoring cleanly.',
  logReplayStartFailed: 'Failed to start historical replay.',
  logConfigSyncFailed: 'Failed to sync configuration to the backend.',
  threatIntelRefreshFailed: 'Failed to refresh threat intelligence feeds.',
  unknownError: 'Unknown error',
};

const de = {
  ...en,
  localeCode: 'de-DE',
  headerTitle: 'NetGuard KI',
  dashboardTitle: 'Operative Netzwerkabwehr',
  dashboardDescription: 'Der Backend-Sensor uebernimmt jetzt Paket-Capture, Heuristik, LLM-Eskalation, Persistenz, Firewall-Aktionen und PCAP-Forensik ohne Browser-Abhaengigkeit.',
  dashboardTab: 'Dashboard',
  settingsTab: 'Einstellungen',
  logsTab: 'Protokolle',
  llmStatusCardTitle: 'LLM-Pipeline',
  blockedDecisionsCardTitle: 'Blockierte Entscheidungen',
  loadedStatus: 'Bereit',
  errorStatus: 'Nicht verfuegbar',
  startingStatus: 'Startet...',
  stoppingStatus: 'Stoppt...',
  persistedHistoryBackend: 'Im Backend persistiert',
  lifetimeCounter: 'Gesamtzaehler',
  captureDeviceLabel: 'Interface',
  startMonitoringButton: 'Ueberwachung starten',
  stopMonitoringButton: 'Ueberwachung stoppen',
  rulesTab: 'Regeln',
  replayStatusLabel: 'Replay',
  replayState_idle: 'Leerlauf',
  replayState_running: 'Laeuft',
  replayState_completed: 'Abgeschlossen',
  replayState_failed: 'Fehlgeschlagen',
  liveTrafficFeed: 'Analysierter Verkehrs-Feed',
  startMonitoringToSeeTraffic: 'Starten Sie die Ueberwachung, um analysierten Verkehr zu sehen.',
  waitingForTraffic: 'Ueberwachung aktiv, warte auf Verkehr.',
  replayTitle: 'Historischer Replay-Modus',
  replayDescription: 'Laden Sie eine PCAP-Datei hoch und spielen Sie sie durch dieselbe Backend-Analysepipeline wie Live-Verkehr.',
  pcapFileLabel: 'PCAP-Datei',
  replaySpeedLabel: 'Replay-Geschwindigkeit',
  replayRunning: 'Replay laeuft...',
  startReplayButton: 'Replay starten',
  replayHint: 'Replay ist deaktiviert, solange Live-Capture aktiv ist. Ein hoeherer Multiplikator beschleunigt die historische Analyse.',
  forensicsTitle: 'PCAP-Forensik',
  forensicsDescription: 'Bedrohungsfenster werden im Backend exportiert und fuer Offline-Analysen in Wireshark bereitgehalten.',
  noArtifactsYet: 'Noch keine PCAP-Artefakte vorhanden.',
  packetsLabel: 'Pakete',
  downloadPcap: 'PCAP herunterladen',
  rawFeedTitle: 'Live-Rohfeed',
  rawFeedDescription: 'Optionaler Rohpaket-Spiegel des Backend-Sensors fuer Troubleshooting und Protokollpruefung.',
  rawFeedSource: 'Quelle',
  rawFeedDestination: 'Ziel',
  rawFeedL7: 'L7',
  rawFeedMetadata: 'Metadaten',
  rawFeedEmpty: 'Aktivieren Sie den Rohfeed und starten Sie das Capture, um dekodierte Pakete zu sehen.',
  colTimestamp: 'Zeitstempel',
  colSourceIp: 'Quell-IP',
  colDestPort: 'Ziel-Port',
  colAttackType: 'Angriffstyp',
  colProcess: 'Lokaler Prozess',
  colAction: 'Aktion',
  colDecisionSource: 'Entscheidungsquelle',
  processFilterLabel: 'Prozessfilter',
  processFilterPlaceholder: 'Nach Prozessname, PID, Pfad, Signatur oder Dienst filtern...',
  processFilterClear: 'Zuruecksetzen',
  processFilterButton: 'So filtern',
  processCopyPath: 'Pfad kopieren',
  processOpenFolder: 'Ordner oeffnen',
  processCompany: 'Binary',
  processSignature: 'Signatur',
  processServices: 'Dienste',
  processActionCopied: 'Prozesspfad wurde in die Zwischenablage kopiert.',
  processActionOpened: 'Prozesspfad wurde im Explorer geoeffnet.',
  processActionFailed: 'Prozessaktion ist fehlgeschlagen.',
  processNoFilterMatches: 'Keine Verkehrszeilen passen zum aktuellen Prozessfilter.',
  processUnavailable: 'Nicht aufgeloest',
  processUnknown: 'Unbekannter Prozess',
  processPathUnavailable: 'Pfad nicht verfuegbar',
  processLocalPort: 'Lokaler Port',
  settingsTitle: 'Einstellungen',
  settingsDescription: 'Die Backend-Konfiguration wird zentral verwaltet. Aenderungen hier werden an den Dienst synchronisiert und serverseitig gespeichert.',
  settingsSensorConfig: 'Sensor & Backend',
  settingsSensorDescription: 'Steuert Backend-Erreichbarkeit, Interface-Auswahl und Rohfeed-Verhalten.',
  settingsLlmConfig: 'LLM-Konfiguration',
  settingsLlmDescription: 'Alle API-Secrets bleiben im Backend. Im Browser werden nur Provider-Routing, Modellwahl und lokale Endpunkte bearbeitet.',
  settingsAnalysisPipeline: 'Analysepipeline',
  settingsAnalysisDescription: 'Konfigurieren Sie Cache, Batching, Schwellenwerte, Redirect-Verhalten und PCAP-Aufbewahrung.',
  settingsIntegrations: 'Integrationen',
  settingsExemptPorts: 'Ausgenommene Ports',
  llmProviderHint: 'Waehlen Sie den Anbieter oder die lokale Laufzeit fuer tiefe Analyse im Backend.',
  backendSecretsTitle: 'Backend-verwaltete Secrets',
  backendSecretsHint: 'API-Schluessel werden nie an den Browser ausgeliefert. Konfigurieren Sie sie auf dem Server ueber Umgebungsvariablen oder einen gesicherten Service-Wrapper.',
  backendSecretsEnvHint: 'Erwartete Umgebungsvariable: {envVar}',
  backendBaseUrl: 'Backend-Basis-URL',
  backendReachable: 'Backend erreichbar',
  backendUnreachable: 'Backend nicht erreichbar',
  refreshInterfaces: 'Interfaces aktualisieren',
  captureInterface: 'Capture-Interface',
  autoSelectInterface: 'Bestes aktives Interface automatisch waehlen',
  liveRawFeedEnabled: 'Live-Rohfeed aktivieren',
  liveRawFeedHint: 'Sendet dekodierte Rohpakete zusaetzlich zu analysierten Events ueber WebSocket.',
  secureRedirectPort: 'Sicherer Redirect-Port',
  pcapBufferSize: 'PCAP-Puffergroesse',
  monitoringPorts: 'Ueberwachungsports (kommagetrennt)',
  detectionThreshold: 'Erkennungsschwelle',
  detectionThresholdHint: 'Konfidenzniveau, ab dem das Backend automatisch blockiert oder umleitet.',
  autoBlockThreats: 'Bedrohungen automatisch blockieren',
  autoBlockThreatsHint: 'Verdachtige Quell-IP-Adressen werden dauerhaft in die Backend-Blockliste aufgenommen.',
  firewallIntegrationEnabled: 'OS-Firewall-Integration aktivieren',
  firewallIntegrationHint: 'Fuehrt echte System-Firewall-Befehle aus, wenn das Backend eine Quell-IP blockieren will.',
  webhookHint: 'Ausgehende Alarme werden vom Backend versendet, damit Integrationen auch im Headless-Betrieb laufen.',
  webhookSummary: '{count} Webhook-Integrationen konfiguriert',
  addWebhook: 'Webhook hinzufuegen',
  webhookName: 'Webhook-Name',
  webhookProvider: 'Webhook-Typ',
  webhookUrl: 'Webhook-URL',
  blockedIpAddresses: 'Blockierte IP-Adressen',
  enterIpAddress: 'IP-Adresse eingeben...',
  blockedPorts: 'Blockierte Ports',
  enterPortNumber: 'Portnummer eingeben...',
  add: 'Hinzufuegen',
  remove: 'Entfernen',
  rulesTitle: 'Custom Rule Builder',
  rulesDescription: 'Erstellen Sie IF/THEN-Regeln, die vor den eingebauten Heuristiken und vor jeder LLM-Eskalation laufen. Treffer koennen Verkehr sofort erlauben, blockieren oder umleiten.',
  addRule: 'Regel hinzufuegen',
  rulesEmptyState: 'Noch keine Custom Rules konfiguriert.',
  newCustomRuleName: 'Neue Custom Rule',
  newCustomRuleExplanation: 'Eine benutzerdefinierte Sicherheitsrichtlinie hat diesen Verkehr getroffen.',
  ruleName: 'Regelname',
  ruleMatchMode: 'Treffermodus',
  ruleMatchModeAll: 'Alle Bedingungen',
  ruleMatchModeAny: 'Mindestens eine Bedingung',
  ruleEnabled: 'Aktiv',
  removeRule: 'Regel entfernen',
  ruleConditions: 'Bedingungen',
  ruleConditionsHint: 'Die Bedingungen werden gegen dekodierte Paketfelder und Layer-7-Metadaten ausgewertet.',
  addCondition: 'Bedingung hinzufuegen',
  ruleField: 'Feld',
  ruleValue: 'Wert',
  ruleOperator: 'Operator',
  ruleOutcome: 'Ergebnis',
  ruleOutcomeHint: 'Definieren Sie Aktion, Angriffstyp, Konfidenz und ob der Treffer trotzdem noch tief analysiert werden soll.',
  ruleAction: 'Aktion',
  ruleAction_allow: 'Erlauben',
  ruleAction_block: 'Blockieren',
  ruleAction_redirect: 'Umleiten',
  ruleAttackType: 'Angriffstyp',
  ruleConfidence: 'Konfidenz',
  ruleRedirectPort: 'Redirect-Port',
  ruleExplanation: 'Erklaerung',
  ruleNeedsDeepInspection: 'Treffer trotzdem an Deep Inspection senden',
  ruleField_sourceIp: 'Quell-IP',
  ruleField_destinationIp: 'Ziel-IP',
  ruleField_sourcePort: 'Quell-Port',
  ruleField_destinationPort: 'Ziel-Port',
  ruleField_protocol: 'Transportprotokoll',
  ruleField_direction: 'Richtung',
  ruleField_size: 'Paketgroesse',
  ruleField_l7Protocol: 'Layer-7-Protokoll',
  ruleField_payloadSnippet: 'Payload-Auszug',
  'ruleField_l7.host': 'HTTP-Host',
  'ruleField_l7.path': 'HTTP-Pfad',
  'ruleField_l7.userAgent': 'HTTP-User-Agent',
  'ruleField_l7.dnsQuery': 'DNS-Query',
  'ruleField_l7.sni': 'TLS-SNI',
  ruleOperator_equals: 'Ist gleich',
  ruleOperator_not_equals: 'Ist ungleich',
  ruleOperator_greater_than: 'Groesser als',
  ruleOperator_less_than: 'Kleiner als',
  ruleOperator_contains: 'Enthaelt',
  ruleOperator_starts_with: 'Beginnt mit',
  ruleOperator_in_cidr: 'In CIDR',
  ruleOperator_not_in_cidr: 'Nicht in CIDR',
  ruleOperator_in_list: 'In Liste',
  ruleOperator_not_in_list: 'Nicht in Liste',
  attackType_port_scan: 'Port-Scan',
  attackType_brute_force: 'Brute Force',
  attackType_malicious_payload: 'Schaedliche Payload',
  attackType_ddos: 'DDoS',
  attackType_none: 'Keiner',
  attackType_other: 'Sonstiges',
  trafficTrendDescription: 'Persistente Telemetrie der letzten 24 Stunden aus dem Backend-Speicher.',
  logsTitle: 'Ereignisprotokolle',
  noLogsYet: 'Noch keine Protokolle. Starten Sie die Ueberwachung, um Ereignisse zu erzeugen.',
  configSyncIdle: 'Synchronisiert',
  configSyncSaving: 'Speichert...',
  configSyncSaved: 'Gespeichert',
  configSyncError: 'Sync fehlgeschlagen',
  logBootstrapFailed: 'Backend-Bootstrap konnte nicht geladen werden.',
  logPacketDecodeFailed: 'Backend-WebSocket-Nachricht konnte nicht dekodiert werden.',
  logWebSocketError: 'Traffic-WebSocket-Fehler',
  logInterfacesRefreshFailed: 'Capture-Interfaces konnten nicht geladen werden.',
  logMonitoringStartFailed: 'Netzwerkueberwachung konnte nicht gestartet werden.',
  logMonitoringStopFailed: 'Netzwerkueberwachung konnte nicht sauber gestoppt werden.',
  logReplayStartFailed: 'Historischer Replay-Start fehlgeschlagen.',
  logConfigSyncFailed: 'Konfiguration konnte nicht mit dem Backend synchronisiert werden.',
  unknownError: 'Unbekannter Fehler',
};

const es = {
  ...en,
  localeCode: 'es-ES',
  dashboardTitle: 'Defensa de red operativa',
  dashboardDescription: 'El sensor backend realiza la captura, heuristicas, escalado a LLM, persistencia, acciones de firewall y forensica PCAP sin depender del navegador.',
  rulesTab: 'Reglas',
  settingsDescription: 'La configuracion del backend se gestiona de forma central y se sincroniza con el servicio.',
};

export const translations = {
  en,
  de,
  es,
  fr: en,
  it: en,
  ja: en,
  nl: de,
  ru: en,
  zh: en,
  ar: en,
};

```

## File: `metadata.json`  
- Path: `metadata.json`  
- Size: 355 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```json
{
  "name": "NetGuard AI",
  "description": "A sophisticated web application that simulates a local network security monitoring tool. It features a real-time traffic feed, uses the Gemini API to emulate an LLM for threat detection, and provides a comprehensive UI for configuration, alerts, and logging.",
  "requestFramePermissions": [],
  "prompt": ""
}
```

## File: `package-lock.json`  
- Path: `package-lock.json`  
- Size: 141237 Bytes  
- Modified: 2026-03-13 14:31:28 UTC

```json
{
  "name": "netguard-ai",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "netguard-ai",
      "version": "0.0.0",
      "dependencies": {
        "@google/genai": "^1.9.0",
        "better-sqlite3": "^12.6.2",
        "cap": "^0.2.1",
        "dexie": "^4.3.0",
        "express": "^5.2.1",
        "lru-cache": "^11.2.6",
        "multer": "^2.1.1",
        "pcap-parser": "^0.2.1",
        "pcap-writer": "^1.0.1",
        "react": "^19.1.0",
        "react-dom": "^19.1.0",
        "recharts": "^3.8.0",
        "ws": "^8.19.0",
        "zod": "^4.3.6"
      },
      "devDependencies": {
        "@types/express": "^5.0.6",
        "@types/node": "^22.14.0",
        "concurrently": "^9.2.1",
        "tsx": "^4.21.0",
        "typescript": "~5.7.2",
        "vite": "^6.2.0"
      }
    },
    "node_modules/@esbuild/aix-ppc64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/aix-ppc64/-/aix-ppc64-0.25.6.tgz",
      "integrity": "sha512-ShbM/3XxwuxjFiuVBHA+d3j5dyac0aEVVq1oluIDf71hUw0aRF59dV/efUsIwFnR6m8JNM2FjZOzmaZ8yG61kw==",
      "cpu": [
        "ppc64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "aix"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/android-arm": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm/-/android-arm-0.25.6.tgz",
      "integrity": "sha512-S8ToEOVfg++AU/bHwdksHNnyLyVM+eMVAOf6yRKFitnwnbwwPNqKr3srzFRe7nzV69RQKb5DgchIX5pt3L53xg==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/android-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm64/-/android-arm64-0.25.6.tgz",
      "integrity": "sha512-hd5zdUarsK6strW+3Wxi5qWws+rJhCCbMiC9QZyzoxfk5uHRIE8T287giQxzVpEvCwuJ9Qjg6bEjcRJcgfLqoA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/android-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/android-x64/-/android-x64-0.25.6.tgz",
      "integrity": "sha512-0Z7KpHSr3VBIO9A/1wcT3NTy7EB4oNC4upJ5ye3R7taCc2GUdeynSLArnon5G8scPwaU866d3H4BCrE5xLW25A==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/darwin-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.25.6.tgz",
      "integrity": "sha512-FFCssz3XBavjxcFxKsGy2DYK5VSvJqa6y5HXljKzhRZ87LvEi13brPrf/wdyl/BbpbMKJNOr1Sd0jtW4Ge1pAA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/darwin-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.25.6.tgz",
      "integrity": "sha512-GfXs5kry/TkGM2vKqK2oyiLFygJRqKVhawu3+DOCk7OxLy/6jYkWXhlHwOoTb0WqGnWGAS7sooxbZowy+pK9Yg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/freebsd-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-arm64/-/freebsd-arm64-0.25.6.tgz",
      "integrity": "sha512-aoLF2c3OvDn2XDTRvn8hN6DRzVVpDlj2B/F66clWd/FHLiHaG3aVZjxQX2DYphA5y/evbdGvC6Us13tvyt4pWg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/freebsd-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-x64/-/freebsd-x64-0.25.6.tgz",
      "integrity": "sha512-2SkqTjTSo2dYi/jzFbU9Plt1vk0+nNg8YC8rOXXea+iA3hfNJWebKYPs3xnOUf9+ZWhKAaxnQNUf2X9LOpeiMQ==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-arm": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm/-/linux-arm-0.25.6.tgz",
      "integrity": "sha512-SZHQlzvqv4Du5PrKE2faN0qlbsaW/3QQfUUc6yO2EjFcA83xnwm91UbEEVx4ApZ9Z5oG8Bxz4qPE+HFwtVcfyw==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm64/-/linux-arm64-0.25.6.tgz",
      "integrity": "sha512-b967hU0gqKd9Drsh/UuAm21Khpoh6mPBSgz8mKRq4P5mVK8bpA+hQzmm/ZwGVULSNBzKdZPQBRT3+WuVavcWsQ==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-ia32": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ia32/-/linux-ia32-0.25.6.tgz",
      "integrity": "sha512-aHWdQ2AAltRkLPOsKdi3xv0mZ8fUGPdlKEjIEhxCPm5yKEThcUjHpWB1idN74lfXGnZ5SULQSgtr5Qos5B0bPw==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-loong64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-loong64/-/linux-loong64-0.25.6.tgz",
      "integrity": "sha512-VgKCsHdXRSQ7E1+QXGdRPlQ/e08bN6WMQb27/TMfV+vPjjTImuT9PmLXupRlC90S1JeNNW5lzkAEO/McKeJ2yg==",
      "cpu": [
        "loong64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-mips64el": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-mips64el/-/linux-mips64el-0.25.6.tgz",
      "integrity": "sha512-WViNlpivRKT9/py3kCmkHnn44GkGXVdXfdc4drNmRl15zVQ2+D2uFwdlGh6IuK5AAnGTo2qPB1Djppj+t78rzw==",
      "cpu": [
        "mips64el"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-ppc64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ppc64/-/linux-ppc64-0.25.6.tgz",
      "integrity": "sha512-wyYKZ9NTdmAMb5730I38lBqVu6cKl4ZfYXIs31Baf8aoOtB4xSGi3THmDYt4BTFHk7/EcVixkOV2uZfwU3Q2Jw==",
      "cpu": [
        "ppc64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-riscv64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-riscv64/-/linux-riscv64-0.25.6.tgz",
      "integrity": "sha512-KZh7bAGGcrinEj4qzilJ4hqTY3Dg2U82c8bv+e1xqNqZCrCyc+TL9AUEn5WGKDzm3CfC5RODE/qc96OcbIe33w==",
      "cpu": [
        "riscv64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-s390x": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-s390x/-/linux-s390x-0.25.6.tgz",
      "integrity": "sha512-9N1LsTwAuE9oj6lHMyyAM+ucxGiVnEqUdp4v7IaMmrwb06ZTEVCIs3oPPplVsnjPfyjmxwHxHMF8b6vzUVAUGw==",
      "cpu": [
        "s390x"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.25.6.tgz",
      "integrity": "sha512-A6bJB41b4lKFWRKNrWoP2LHsjVzNiaurf7wyj/XtFNTsnPuxwEBWHLty+ZE0dWBKuSK1fvKgrKaNjBS7qbFKig==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/netbsd-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-arm64/-/netbsd-arm64-0.25.6.tgz",
      "integrity": "sha512-IjA+DcwoVpjEvyxZddDqBY+uJ2Snc6duLpjmkXm/v4xuS3H+3FkLZlDm9ZsAbF9rsfP3zeA0/ArNDORZgrxR/Q==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/netbsd-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-x64/-/netbsd-x64-0.25.6.tgz",
      "integrity": "sha512-dUXuZr5WenIDlMHdMkvDc1FAu4xdWixTCRgP7RQLBOkkGgwuuzaGSYcOpW4jFxzpzL1ejb8yF620UxAqnBrR9g==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/openbsd-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-arm64/-/openbsd-arm64-0.25.6.tgz",
      "integrity": "sha512-l8ZCvXP0tbTJ3iaqdNf3pjaOSd5ex/e6/omLIQCVBLmHTlfXW3zAxQ4fnDmPLOB1x9xrcSi/xtCWFwCZRIaEwg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/openbsd-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-x64/-/openbsd-x64-0.25.6.tgz",
      "integrity": "sha512-hKrmDa0aOFOr71KQ/19JC7az1P0GWtCN1t2ahYAf4O007DHZt/dW8ym5+CUdJhQ/qkZmI1HAF8KkJbEFtCL7gw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/openharmony-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/openharmony-arm64/-/openharmony-arm64-0.25.6.tgz",
      "integrity": "sha512-+SqBcAWoB1fYKmpWoQP4pGtx+pUUC//RNYhFdbcSA16617cchuryuhOCRpPsjCblKukAckWsV+aQ3UKT/RMPcA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openharmony"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/sunos-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/sunos-x64/-/sunos-x64-0.25.6.tgz",
      "integrity": "sha512-dyCGxv1/Br7MiSC42qinGL8KkG4kX0pEsdb0+TKhmJZgCUDBGmyo1/ArCjNGiOLiIAgdbWgmWgib4HoCi5t7kA==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "sunos"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/win32-arm64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-arm64/-/win32-arm64-0.25.6.tgz",
      "integrity": "sha512-42QOgcZeZOvXfsCBJF5Afw73t4veOId//XD3i+/9gSkhSV6Gk3VPlWncctI+JcOyERv85FUo7RxuxGy+z8A43Q==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/win32-ia32": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-ia32/-/win32-ia32-0.25.6.tgz",
      "integrity": "sha512-4AWhgXmDuYN7rJI6ORB+uU9DHLq/erBbuMoAuB4VWJTu5KtCgcKYPynF0YI1VkBNuEfjNlLrFr9KZPJzrtLkrQ==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/win32-x64": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-0.25.6.tgz",
      "integrity": "sha512-NgJPHHbEpLQgDH2MjQu90pzW/5vvXIZ7KOnPyNBm92A6WgZ/7b6fJyUBjoumLqeOQQGqY2QjQxRo97ah4Sj0cA==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@google/genai": {
      "version": "1.9.0",
      "resolved": "https://registry.npmjs.org/@google/genai/-/genai-1.9.0.tgz",
      "integrity": "sha512-w9P93OXKPMs9H1mfAx9+p3zJqQGrWBGdvK/SVc7cLZEXNHr/3+vW2eif7ZShA6wU24rNLn9z9MK2vQFUvNRI2Q==",
      "license": "Apache-2.0",
      "dependencies": {
        "google-auth-library": "^9.14.2",
        "ws": "^8.18.0"
      },
      "engines": {
        "node": ">=20.0.0"
      },
      "peerDependencies": {
        "@modelcontextprotocol/sdk": "^1.11.0"
      },
      "peerDependenciesMeta": {
        "@modelcontextprotocol/sdk": {
          "optional": true
        }
      }
    },
    "node_modules/@reduxjs/toolkit": {
      "version": "2.11.2",
      "resolved": "https://registry.npmjs.org/@reduxjs/toolkit/-/toolkit-2.11.2.tgz",
      "integrity": "sha512-Kd6kAHTA6/nUpp8mySPqj3en3dm0tdMIgbttnQ1xFMVpufoj+ADi8pXLBsd4xzTRHQa7t/Jv8W5UnCuW4kuWMQ==",
      "license": "MIT",
      "dependencies": {
        "@standard-schema/spec": "^1.0.0",
        "@standard-schema/utils": "^0.3.0",
        "immer": "^11.0.0",
        "redux": "^5.0.1",
        "redux-thunk": "^3.1.0",
        "reselect": "^5.1.0"
      },
      "peerDependencies": {
        "react": "^16.9.0 || ^17.0.0 || ^18 || ^19",
        "react-redux": "^7.2.1 || ^8.1.3 || ^9.0.0"
      },
      "peerDependenciesMeta": {
        "react": {
          "optional": true
        },
        "react-redux": {
          "optional": true
        }
      }
    },
    "node_modules/@reduxjs/toolkit/node_modules/immer": {
      "version": "11.1.4",
      "resolved": "https://registry.npmjs.org/immer/-/immer-11.1.4.tgz",
      "integrity": "sha512-XREFCPo6ksxVzP4E0ekD5aMdf8WMwmdNaz6vuvxgI40UaEiu6q3p8X52aU6GdyvLY3XXX/8R7JOTXStz/nBbRw==",
      "license": "MIT",
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/immer"
      }
    },
    "node_modules/@rollup/rollup-android-arm-eabi": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-android-arm-eabi/-/rollup-android-arm-eabi-4.45.1.tgz",
      "integrity": "sha512-NEySIFvMY0ZQO+utJkgoMiCAjMrGvnbDLHvcmlA33UXJpYBCvlBEbMMtV837uCkS+plG2umfhn0T5mMAxGrlRA==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ]
    },
    "node_modules/@rollup/rollup-android-arm64": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-android-arm64/-/rollup-android-arm64-4.45.1.tgz",
      "integrity": "sha512-ujQ+sMXJkg4LRJaYreaVx7Z/VMgBBd89wGS4qMrdtfUFZ+TSY5Rs9asgjitLwzeIbhwdEhyj29zhst3L1lKsRQ==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ]
    },
    "node_modules/@rollup/rollup-darwin-arm64": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-darwin-arm64/-/rollup-darwin-arm64-4.45.1.tgz",
      "integrity": "sha512-FSncqHvqTm3lC6Y13xncsdOYfxGSLnP+73k815EfNmpewPs+EyM49haPS105Rh4aF5mJKywk9X0ogzLXZzN9lA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ]
    },
    "node_modules/@rollup/rollup-darwin-x64": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-darwin-x64/-/rollup-darwin-x64-4.45.1.tgz",
      "integrity": "sha512-2/vVn/husP5XI7Fsf/RlhDaQJ7x9zjvC81anIVbr4b/f0xtSmXQTFcGIQ/B1cXIYM6h2nAhJkdMHTnD7OtQ9Og==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ]
    },
    "node_modules/@rollup/rollup-freebsd-arm64": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-freebsd-arm64/-/rollup-freebsd-arm64-4.45.1.tgz",
      "integrity": "sha512-4g1kaDxQItZsrkVTdYQ0bxu4ZIQ32cotoQbmsAnW1jAE4XCMbcBPDirX5fyUzdhVCKgPcrwWuucI8yrVRBw2+g==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ]
    },
    "node_modules/@rollup/rollup-freebsd-x64": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-freebsd-x64/-/rollup-freebsd-x64-4.45.1.tgz",
      "integrity": "sha512-L/6JsfiL74i3uK1Ti2ZFSNsp5NMiM4/kbbGEcOCps99aZx3g8SJMO1/9Y0n/qKlWZfn6sScf98lEOUe2mBvW9A==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ]
    },
    "node_modules/@rollup/rollup-linux-arm-gnueabihf": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-arm-gnueabihf/-/rollup-linux-arm-gnueabihf-4.45.1.tgz",
      "integrity": "sha512-RkdOTu2jK7brlu+ZwjMIZfdV2sSYHK2qR08FUWcIoqJC2eywHbXr0L8T/pONFwkGukQqERDheaGTeedG+rra6Q==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-arm-musleabihf": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-arm-musleabihf/-/rollup-linux-arm-musleabihf-4.45.1.tgz",
      "integrity": "sha512-3kJ8pgfBt6CIIr1o+HQA7OZ9mp/zDk3ctekGl9qn/pRBgrRgfwiffaUmqioUGN9hv0OHv2gxmvdKOkARCtRb8Q==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-arm64-gnu": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-arm64-gnu/-/rollup-linux-arm64-gnu-4.45.1.tgz",
      "integrity": "sha512-k3dOKCfIVixWjG7OXTCOmDfJj3vbdhN0QYEqB+OuGArOChek22hn7Uy5A/gTDNAcCy5v2YcXRJ/Qcnm4/ma1xw==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-arm64-musl": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-arm64-musl/-/rollup-linux-arm64-musl-4.45.1.tgz",
      "integrity": "sha512-PmI1vxQetnM58ZmDFl9/Uk2lpBBby6B6rF4muJc65uZbxCs0EA7hhKCk2PKlmZKuyVSHAyIw3+/SiuMLxKxWog==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-loongarch64-gnu": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-loongarch64-gnu/-/rollup-linux-loongarch64-gnu-4.45.1.tgz",
      "integrity": "sha512-9UmI0VzGmNJ28ibHW2GpE2nF0PBQqsyiS4kcJ5vK+wuwGnV5RlqdczVocDSUfGX/Na7/XINRVoUgJyFIgipoRg==",
      "cpu": [
        "loong64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-powerpc64le-gnu": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-powerpc64le-gnu/-/rollup-linux-powerpc64le-gnu-4.45.1.tgz",
      "integrity": "sha512-7nR2KY8oEOUTD3pBAxIBBbZr0U7U+R9HDTPNy+5nVVHDXI4ikYniH1oxQz9VoB5PbBU1CZuDGHkLJkd3zLMWsg==",
      "cpu": [
        "ppc64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-riscv64-gnu": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-riscv64-gnu/-/rollup-linux-riscv64-gnu-4.45.1.tgz",
      "integrity": "sha512-nlcl3jgUultKROfZijKjRQLUu9Ma0PeNv/VFHkZiKbXTBQXhpytS8CIj5/NfBeECZtY2FJQubm6ltIxm/ftxpw==",
      "cpu": [
        "riscv64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-riscv64-musl": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-riscv64-musl/-/rollup-linux-riscv64-musl-4.45.1.tgz",
      "integrity": "sha512-HJV65KLS51rW0VY6rvZkiieiBnurSzpzore1bMKAhunQiECPuxsROvyeaot/tcK3A3aGnI+qTHqisrpSgQrpgA==",
      "cpu": [
        "riscv64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-s390x-gnu": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-s390x-gnu/-/rollup-linux-s390x-gnu-4.45.1.tgz",
      "integrity": "sha512-NITBOCv3Qqc6hhwFt7jLV78VEO/il4YcBzoMGGNxznLgRQf43VQDae0aAzKiBeEPIxnDrACiMgbqjuihx08OOw==",
      "cpu": [
        "s390x"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-x64-gnu": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-x64-gnu/-/rollup-linux-x64-gnu-4.45.1.tgz",
      "integrity": "sha512-+E/lYl6qu1zqgPEnTrs4WysQtvc/Sh4fC2nByfFExqgYrqkKWp1tWIbe+ELhixnenSpBbLXNi6vbEEJ8M7fiHw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-linux-x64-musl": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-x64-musl/-/rollup-linux-x64-musl-4.45.1.tgz",
      "integrity": "sha512-a6WIAp89p3kpNoYStITT9RbTbTnqarU7D8N8F2CV+4Cl9fwCOZraLVuVFvlpsW0SbIiYtEnhCZBPLoNdRkjQFw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ]
    },
    "node_modules/@rollup/rollup-win32-arm64-msvc": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-win32-arm64-msvc/-/rollup-win32-arm64-msvc-4.45.1.tgz",
      "integrity": "sha512-T5Bi/NS3fQiJeYdGvRpTAP5P02kqSOpqiopwhj0uaXB6nzs5JVi2XMJb18JUSKhCOX8+UE1UKQufyD6Or48dJg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ]
    },
    "node_modules/@rollup/rollup-win32-ia32-msvc": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-win32-ia32-msvc/-/rollup-win32-ia32-msvc-4.45.1.tgz",
      "integrity": "sha512-lxV2Pako3ujjuUe9jiU3/s7KSrDfH6IgTSQOnDWr9aJ92YsFd7EurmClK0ly/t8dzMkDtd04g60WX6yl0sGfdw==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ]
    },
    "node_modules/@rollup/rollup-win32-x64-msvc": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/@rollup/rollup-win32-x64-msvc/-/rollup-win32-x64-msvc-4.45.1.tgz",
      "integrity": "sha512-M/fKi4sasCdM8i0aWJjCSFm2qEnYRR8AMLG2kxp6wD13+tMGA4Z1tVAuHkNRjud5SW2EM3naLuK35w9twvf6aA==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ]
    },
    "node_modules/@standard-schema/spec": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/@standard-schema/spec/-/spec-1.1.0.tgz",
      "integrity": "sha512-l2aFy5jALhniG5HgqrD6jXLi/rUWrKvqN/qJx6yoJsgKhblVd+iqqU4RCXavm/jPityDo5TCvKMnpjKnOriy0w==",
      "license": "MIT"
    },
    "node_modules/@standard-schema/utils": {
      "version": "0.3.0",
      "resolved": "https://registry.npmjs.org/@standard-schema/utils/-/utils-0.3.0.tgz",
      "integrity": "sha512-e7Mew686owMaPJVNNLs55PUvgz371nKgwsc4vxE49zsODpJEnxgxRo2y/OKrqueavXgZNMDVj3DdHFlaSAeU8g==",
      "license": "MIT"
    },
    "node_modules/@types/body-parser": {
      "version": "1.19.6",
      "resolved": "https://registry.npmjs.org/@types/body-parser/-/body-parser-1.19.6.tgz",
      "integrity": "sha512-HLFeCYgz89uk22N5Qg3dvGvsv46B8GLvKKo1zKG4NybA8U2DiEO3w9lqGg29t/tfLRJpJ6iQxnVw4OnB7MoM9g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/connect": "*",
        "@types/node": "*"
      }
    },
    "node_modules/@types/connect": {
      "version": "3.4.38",
      "resolved": "https://registry.npmjs.org/@types/connect/-/connect-3.4.38.tgz",
      "integrity": "sha512-K6uROf1LD88uDQqJCktA4yzL1YYAK6NgfsI0v/mTgyPKWsX1CnJ0XPSDhViejru1GcRkLWb8RlzFYJRqGUbaug==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/node": "*"
      }
    },
    "node_modules/@types/d3-array": {
      "version": "3.2.2",
      "resolved": "https://registry.npmjs.org/@types/d3-array/-/d3-array-3.2.2.tgz",
      "integrity": "sha512-hOLWVbm7uRza0BYXpIIW5pxfrKe0W+D5lrFiAEYR+pb6w3N2SwSMaJbXdUfSEv+dT4MfHBLtn5js0LAWaO6otw==",
      "license": "MIT"
    },
    "node_modules/@types/d3-color": {
      "version": "3.1.3",
      "resolved": "https://registry.npmjs.org/@types/d3-color/-/d3-color-3.1.3.tgz",
      "integrity": "sha512-iO90scth9WAbmgv7ogoq57O9YpKmFBbmoEoCHDB2xMBY0+/KVrqAaCDyCE16dUspeOvIxFFRI+0sEtqDqy2b4A==",
      "license": "MIT"
    },
    "node_modules/@types/d3-ease": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/@types/d3-ease/-/d3-ease-3.0.2.tgz",
      "integrity": "sha512-NcV1JjO5oDzoK26oMzbILE6HW7uVXOHLQvHshBUW4UMdZGfiY6v5BeQwh9a9tCzv+CeefZQHJt5SRgK154RtiA==",
      "license": "MIT"
    },
    "node_modules/@types/d3-interpolate": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/@types/d3-interpolate/-/d3-interpolate-3.0.4.tgz",
      "integrity": "sha512-mgLPETlrpVV1YRJIglr4Ez47g7Yxjl1lj7YKsiMCb27VJH9W8NVM6Bb9d8kkpG/uAQS5AmbA48q2IAolKKo1MA==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-color": "*"
      }
    },
    "node_modules/@types/d3-path": {
      "version": "3.1.1",
      "resolved": "https://registry.npmjs.org/@types/d3-path/-/d3-path-3.1.1.tgz",
      "integrity": "sha512-VMZBYyQvbGmWyWVea0EHs/BwLgxc+MKi1zLDCONksozI4YJMcTt8ZEuIR4Sb1MMTE8MMW49v0IwI5+b7RmfWlg==",
      "license": "MIT"
    },
    "node_modules/@types/d3-scale": {
      "version": "4.0.9",
      "resolved": "https://registry.npmjs.org/@types/d3-scale/-/d3-scale-4.0.9.tgz",
      "integrity": "sha512-dLmtwB8zkAeO/juAMfnV+sItKjlsw2lKdZVVy6LRr0cBmegxSABiLEpGVmSJJ8O08i4+sGR6qQtb6WtuwJdvVw==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-time": "*"
      }
    },
    "node_modules/@types/d3-shape": {
      "version": "3.1.8",
      "resolved": "https://registry.npmjs.org/@types/d3-shape/-/d3-shape-3.1.8.tgz",
      "integrity": "sha512-lae0iWfcDeR7qt7rA88BNiqdvPS5pFVPpo5OfjElwNaT2yyekbM0C9vK+yqBqEmHr6lDkRnYNoTBYlAgJa7a4w==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-path": "*"
      }
    },
    "node_modules/@types/d3-time": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/@types/d3-time/-/d3-time-3.0.4.tgz",
      "integrity": "sha512-yuzZug1nkAAaBlBBikKZTgzCeA+k1uy4ZFwWANOfKw5z5LRhV0gNA7gNkKm7HoK+HRN0wX3EkxGk0fpbWhmB7g==",
      "license": "MIT"
    },
    "node_modules/@types/d3-timer": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/@types/d3-timer/-/d3-timer-3.0.2.tgz",
      "integrity": "sha512-Ps3T8E8dZDam6fUyNiMkekK3XUsaUEik+idO9/YjPtfj2qruF8tFBXS7XhtE4iIXBLxhmLjP3SXpLhVf21I9Lw==",
      "license": "MIT"
    },
    "node_modules/@types/estree": {
      "version": "1.0.8",
      "resolved": "https://registry.npmjs.org/@types/estree/-/estree-1.0.8.tgz",
      "integrity": "sha512-dWHzHa2WqEXI/O1E9OjrocMTKJl2mSrEolh1Iomrv6U+JuNwaHXsXx9bLu5gG7BUWFIN0skIQJQ/L1rIex4X6w==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@types/express": {
      "version": "5.0.6",
      "resolved": "https://registry.npmjs.org/@types/express/-/express-5.0.6.tgz",
      "integrity": "sha512-sKYVuV7Sv9fbPIt/442koC7+IIwK5olP1KWeD88e/idgoJqDm3JV/YUiPwkoKK92ylff2MGxSz1CSjsXelx0YA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/body-parser": "*",
        "@types/express-serve-static-core": "^5.0.0",
        "@types/serve-static": "^2"
      }
    },
    "node_modules/@types/express-serve-static-core": {
      "version": "5.1.1",
      "resolved": "https://registry.npmjs.org/@types/express-serve-static-core/-/express-serve-static-core-5.1.1.tgz",
      "integrity": "sha512-v4zIMr/cX7/d2BpAEX3KNKL/JrT1s43s96lLvvdTmza1oEvDudCqK9aF/djc/SWgy8Yh0h30TZx5VpzqFCxk5A==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/node": "*",
        "@types/qs": "*",
        "@types/range-parser": "*",
        "@types/send": "*"
      }
    },
    "node_modules/@types/http-errors": {
      "version": "2.0.5",
      "resolved": "https://registry.npmjs.org/@types/http-errors/-/http-errors-2.0.5.tgz",
      "integrity": "sha512-r8Tayk8HJnX0FztbZN7oVqGccWgw98T/0neJphO91KkmOzug1KkofZURD4UaD5uH8AqcFLfdPErnBod0u71/qg==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@types/node": {
      "version": "22.16.4",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-22.16.4.tgz",
      "integrity": "sha512-PYRhNtZdm2wH/NT2k/oAJ6/f2VD2N2Dag0lGlx2vWgMSJXGNmlce5MiTQzoWAiIJtso30mjnfQCOKVH+kAQC/g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "undici-types": "~6.21.0"
      }
    },
    "node_modules/@types/qs": {
      "version": "6.15.0",
      "resolved": "https://registry.npmjs.org/@types/qs/-/qs-6.15.0.tgz",
      "integrity": "sha512-JawvT8iBVWpzTrz3EGw9BTQFg3BQNmwERdKE22vlTxawwtbyUSlMppvZYKLZzB5zgACXdXxbD3m1bXaMqP/9ow==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@types/range-parser": {
      "version": "1.2.7",
      "resolved": "https://registry.npmjs.org/@types/range-parser/-/range-parser-1.2.7.tgz",
      "integrity": "sha512-hKormJbkJqzQGhziax5PItDUTMAM9uE2XXQmM37dyd4hVM+5aVl7oVxMVUiVQn2oCQFN/LKCZdvSM0pFRqbSmQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@types/send": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/@types/send/-/send-1.2.1.tgz",
      "integrity": "sha512-arsCikDvlU99zl1g69TcAB3mzZPpxgw0UQnaHeC1Nwb015xp8bknZv5rIfri9xTOcMuaVgvabfIRA7PSZVuZIQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/node": "*"
      }
    },
    "node_modules/@types/serve-static": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/@types/serve-static/-/serve-static-2.2.0.tgz",
      "integrity": "sha512-8mam4H1NHLtu7nmtalF7eyBH14QyOASmcxHhSfEoRyr0nP/YdoesEtU+uSRvMe96TW/HPTtkoKqQLl53N7UXMQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/http-errors": "*",
        "@types/node": "*"
      }
    },
    "node_modules/@types/use-sync-external-store": {
      "version": "0.0.6",
      "resolved": "https://registry.npmjs.org/@types/use-sync-external-store/-/use-sync-external-store-0.0.6.tgz",
      "integrity": "sha512-zFDAD+tlpf2r4asuHEj0XH6pY6i0g5NeAHPn+15wk3BV6JA69eERFXC1gyGThDkVa1zCyKr5jox1+2LbV/AMLg==",
      "license": "MIT"
    },
    "node_modules/accepts": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/accepts/-/accepts-2.0.0.tgz",
      "integrity": "sha512-5cvg6CtKwfgdmVqY1WIiXKc3Q1bkRqGLi+2W/6ao+6Y7gu/RCwRuAhGEzh5B4KlszSuTLgZYuqFqo5bImjNKng==",
      "license": "MIT",
      "dependencies": {
        "mime-types": "^3.0.0",
        "negotiator": "^1.0.0"
      },
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/agent-base": {
      "version": "7.1.4",
      "resolved": "https://registry.npmjs.org/agent-base/-/agent-base-7.1.4.tgz",
      "integrity": "sha512-MnA+YT8fwfJPgBx3m60MNqakm30XOkyIoH1y6huTQvC0PwZG7ki8NacLBcrPbNoo8vEZy7Jpuk7+jMO+CUovTQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 14"
      }
    },
    "node_modules/ansi-regex": {
      "version": "5.0.1",
      "resolved": "https://registry.npmjs.org/ansi-regex/-/ansi-regex-5.0.1.tgz",
      "integrity": "sha512-quJQXlTSUGL2LH9SUXo8VwsY4soanhgo6LNSm84E1LBcE8s3O0wpdiRzyR9z/ZZJMlMWv37qOOb9pdJlMUEKFQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/ansi-styles": {
      "version": "4.3.0",
      "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz",
      "integrity": "sha512-zbB9rCJAT1rbjiVDb2hqKFHNYLxgtk8NURxZ3IZwD3F6NtxbXZQCnnSi1Lkx+IDohdPlFp222wVALIheZJQSEg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "color-convert": "^2.0.1"
      },
      "engines": {
        "node": ">=8"
      },
      "funding": {
        "url": "https://github.com/chalk/ansi-styles?sponsor=1"
      }
    },
    "node_modules/append-field": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/append-field/-/append-field-1.0.0.tgz",
      "integrity": "sha512-klpgFSWLW1ZEs8svjfb7g4qWY0YS5imI82dTg+QahUvJ8YqAY0P10Uk8tTyh9ZGuYEZEMaeJYCF5BFuX552hsw==",
      "license": "MIT"
    },
    "node_modules/base64-js": {
      "version": "1.5.1",
      "resolved": "https://registry.npmjs.org/base64-js/-/base64-js-1.5.1.tgz",
      "integrity": "sha512-AKpaYlHn8t4SVbOHCy+b5+KKgvR4vrsD8vbvrbiQJps7fKDTkjkDry6ji0rUJjC0kzbNePLwzxq8iypo41qeWA==",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT"
    },
    "node_modules/better-sqlite3": {
      "version": "12.6.2",
      "resolved": "https://registry.npmjs.org/better-sqlite3/-/better-sqlite3-12.6.2.tgz",
      "integrity": "sha512-8VYKM3MjCa9WcaSAI3hzwhmyHVlH8tiGFwf0RlTsZPWJ1I5MkzjiudCo4KC4DxOaL/53A5B1sI/IbldNFDbsKA==",
      "hasInstallScript": true,
      "license": "MIT",
      "dependencies": {
        "bindings": "^1.5.0",
        "prebuild-install": "^7.1.1"
      },
      "engines": {
        "node": "20.x || 22.x || 23.x || 24.x || 25.x"
      }
    },
    "node_modules/bignumber.js": {
      "version": "9.3.1",
      "resolved": "https://registry.npmjs.org/bignumber.js/-/bignumber.js-9.3.1.tgz",
      "integrity": "sha512-Ko0uX15oIUS7wJ3Rb30Fs6SkVbLmPBAKdlm7q9+ak9bbIeFf0MwuBsQV6z7+X768/cHsfg+WlysDWJcmthjsjQ==",
      "license": "MIT",
      "engines": {
        "node": "*"
      }
    },
    "node_modules/bindings": {
      "version": "1.5.0",
      "resolved": "https://registry.npmjs.org/bindings/-/bindings-1.5.0.tgz",
      "integrity": "sha512-p2q/t/mhvuOj/UeLlV6566GD/guowlr0hHxClI0W9m7MWYkL1F0hLo+0Aexs9HSPCtR1SXQ0TD3MMKrXZajbiQ==",
      "license": "MIT",
      "dependencies": {
        "file-uri-to-path": "1.0.0"
      }
    },
    "node_modules/bl": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/bl/-/bl-4.1.0.tgz",
      "integrity": "sha512-1W07cM9gS6DcLperZfFSj+bWLtaPGSOHWhPiGzXmvVJbRLdG82sH/Kn8EtW1VqWVA54AKf2h5k5BbnIbwF3h6w==",
      "license": "MIT",
      "dependencies": {
        "buffer": "^5.5.0",
        "inherits": "^2.0.4",
        "readable-stream": "^3.4.0"
      }
    },
    "node_modules/body-parser": {
      "version": "2.2.2",
      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-2.2.2.tgz",
      "integrity": "sha512-oP5VkATKlNwcgvxi0vM0p/D3n2C3EReYVX+DNYs5TjZFn/oQt2j+4sVJtSMr18pdRr8wjTcBl6LoV+FUwzPmNA==",
      "license": "MIT",
      "dependencies": {
        "bytes": "^3.1.2",
        "content-type": "^1.0.5",
        "debug": "^4.4.3",
        "http-errors": "^2.0.0",
        "iconv-lite": "^0.7.0",
        "on-finished": "^2.4.1",
        "qs": "^6.14.1",
        "raw-body": "^3.0.1",
        "type-is": "^2.0.1"
      },
      "engines": {
        "node": ">=18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/buffer": {
      "version": "5.7.1",
      "resolved": "https://registry.npmjs.org/buffer/-/buffer-5.7.1.tgz",
      "integrity": "sha512-EHcyIPBQ4BSGlvjB16k5KgAJ27CIsHY/2JBmCRReo48y9rQ3MaUzWX3KVlBa4U7MyX02HdVj0K7C3WaB3ju7FQ==",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "base64-js": "^1.3.1",
        "ieee754": "^1.1.13"
      }
    },
    "node_modules/buffer-equal-constant-time": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/buffer-equal-constant-time/-/buffer-equal-constant-time-1.0.1.tgz",
      "integrity": "sha512-zRpUiDwd/xk6ADqPMATG8vc9VPrkck7T07OIx0gnjmJAnHnTVXNQG3vfvWNuiZIkwu9KrKdA1iJKfsfTVxE6NA==",
      "license": "BSD-3-Clause"
    },
    "node_modules/buffer-from": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/buffer-from/-/buffer-from-1.1.2.tgz",
      "integrity": "sha512-E+XQCRwSbaaiChtv6k6Dwgc+bx+Bs6vuKJHHl5kox/BaKbhiXzqQOwK4cO22yElGp2OCmjwVhT3HmxgyPGnJfQ==",
      "license": "MIT"
    },
    "node_modules/bufferpack": {
      "version": "0.0.6",
      "resolved": "https://registry.npmjs.org/bufferpack/-/bufferpack-0.0.6.tgz",
      "integrity": "sha512-MTWvLHElqczrIVhge9qHtqgNigJFyh0+tCDId5yCbFAfuekHWIG+uAgvoHVflwrDPuY/e47JE1ki5qcM7w4uLg==",
      "engines": {
        "node": "*"
      }
    },
    "node_modules/busboy": {
      "version": "1.6.0",
      "resolved": "https://registry.npmjs.org/busboy/-/busboy-1.6.0.tgz",
      "integrity": "sha512-8SFQbg/0hQ9xy3UNTB0YEnsNBbWfhf7RtnzpL7TkBiTBRfrQ9Fxcnz7VJsleJpyp6rVLvXiuORqjlHi5q+PYuA==",
      "dependencies": {
        "streamsearch": "^1.1.0"
      },
      "engines": {
        "node": ">=10.16.0"
      }
    },
    "node_modules/bytes": {
      "version": "3.1.2",
      "resolved": "https://registry.npmjs.org/bytes/-/bytes-3.1.2.tgz",
      "integrity": "sha512-/Nf7TyzTx6S3yRJObOAV7956r8cr2+Oj8AC5dt8wSP3BQAoeX58NoHyCU8P8zGkNXStjTSi6fzO6F0pBdcYbEg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/call-bind-apply-helpers": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/call-bind-apply-helpers/-/call-bind-apply-helpers-1.0.2.tgz",
      "integrity": "sha512-Sp1ablJ0ivDkSzjcaJdxEunN5/XvksFJ2sMBFfq6x0ryhQV/2b/KwFe21cMpmHtPOSij8K99/wSfoEuTObmuMQ==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0",
        "function-bind": "^1.1.2"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/call-bound": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/call-bound/-/call-bound-1.0.4.tgz",
      "integrity": "sha512-+ys997U96po4Kx/ABpBCqhA9EuxJaQWDQg7295H4hBphv3IZg0boBKuwYpt4YXp6MZ5AmZQnU/tyMTlRpaSejg==",
      "license": "MIT",
      "dependencies": {
        "call-bind-apply-helpers": "^1.0.2",
        "get-intrinsic": "^1.3.0"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/cap": {
      "version": "0.2.1",
      "resolved": "https://registry.npmjs.org/cap/-/cap-0.2.1.tgz",
      "integrity": "sha512-0n10YndTkI4V+rsPVvYFdqlA0Bjf8NFlP/Wgp0W0ymudkijuqkmSVdIWigFe2YdPhjjxTJdW9Mu5ee4VwB0L+A==",
      "hasInstallScript": true,
      "dependencies": {
        "nan": "^2.14.0"
      },
      "engines": {
        "node": ">=4.0.0"
      }
    },
    "node_modules/chalk": {
      "version": "4.1.2",
      "resolved": "https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz",
      "integrity": "sha512-oKnbhFyRIXpUuez8iBMmyEa4nbj4IOQyuhc/wy9kY7/WVPcwIO9VA668Pu8RkO7+0G76SLROeyw9CpQ061i4mA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "ansi-styles": "^4.1.0",
        "supports-color": "^7.1.0"
      },
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/chalk/chalk?sponsor=1"
      }
    },
    "node_modules/chalk/node_modules/supports-color": {
      "version": "7.2.0",
      "resolved": "https://registry.npmjs.org/supports-color/-/supports-color-7.2.0.tgz",
      "integrity": "sha512-qpCAvRl9stuOHveKsn7HncJRvv501qIacKzQlO/+Lwxc9+0q2wLyv4Dfvt80/DPn2pqOBsJdDiogXGR9+OvwRw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "has-flag": "^4.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/chownr": {
      "version": "1.1.4",
      "resolved": "https://registry.npmjs.org/chownr/-/chownr-1.1.4.tgz",
      "integrity": "sha512-jJ0bqzaylmJtVnNgzTeSOs8DPavpbYgEr/b0YL8/2GO3xJEhInFmhKMUnEJQjZumK7KXGFhUy89PrsJWlakBVg==",
      "license": "ISC"
    },
    "node_modules/cliui": {
      "version": "8.0.1",
      "resolved": "https://registry.npmjs.org/cliui/-/cliui-8.0.1.tgz",
      "integrity": "sha512-BSeNnyus75C4//NQ9gQt1/csTXyo/8Sb+afLAkzAptFuMsod9HFokGNudZpi/oQV73hnVK+sR+5PVRMd+Dr7YQ==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "string-width": "^4.2.0",
        "strip-ansi": "^6.0.1",
        "wrap-ansi": "^7.0.0"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/clsx": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/clsx/-/clsx-2.1.1.tgz",
      "integrity": "sha512-eYm0QWBtUrBWZWG0d386OGAw16Z995PiOVo2B7bjWSbHedGl5e0ZWaq65kOGgUSNesEIDkB9ISbTg/JK9dhCZA==",
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/color-convert": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/color-convert/-/color-convert-2.0.1.tgz",
      "integrity": "sha512-RRECPsj7iu/xb5oKYcsFHSppFNnsj/52OVTRKb4zP5onXwVF3zVmmToNcOfGC+CRDpfK/U584fMg38ZHCaElKQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "color-name": "~1.1.4"
      },
      "engines": {
        "node": ">=7.0.0"
      }
    },
    "node_modules/color-name": {
      "version": "1.1.4",
      "resolved": "https://registry.npmjs.org/color-name/-/color-name-1.1.4.tgz",
      "integrity": "sha512-dOy+3AuW3a2wNbZHIuMZpTcgjGuLU/uBL/ubcZF9OXbDo8ff4O8yVp5Bf0efS8uEoYo5q4Fx7dY9OgQGXgAsQA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/concat-stream": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/concat-stream/-/concat-stream-2.0.0.tgz",
      "integrity": "sha512-MWufYdFw53ccGjCA+Ol7XJYpAlW6/prSMzuPOTRnJGcGzuhLn4Scrz7qf6o8bROZ514ltazcIFJZevcfbo0x7A==",
      "engines": [
        "node >= 6.0"
      ],
      "license": "MIT",
      "dependencies": {
        "buffer-from": "^1.0.0",
        "inherits": "^2.0.3",
        "readable-stream": "^3.0.2",
        "typedarray": "^0.0.6"
      }
    },
    "node_modules/concurrently": {
      "version": "9.2.1",
      "resolved": "https://registry.npmjs.org/concurrently/-/concurrently-9.2.1.tgz",
      "integrity": "sha512-fsfrO0MxV64Znoy8/l1vVIjjHa29SZyyqPgQBwhiDcaW8wJc2W3XWVOGx4M3oJBnv/zdUZIIp1gDeS98GzP8Ng==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "chalk": "4.1.2",
        "rxjs": "7.8.2",
        "shell-quote": "1.8.3",
        "supports-color": "8.1.1",
        "tree-kill": "1.2.2",
        "yargs": "17.7.2"
      },
      "bin": {
        "conc": "dist/bin/concurrently.js",
        "concurrently": "dist/bin/concurrently.js"
      },
      "engines": {
        "node": ">=18"
      },
      "funding": {
        "url": "https://github.com/open-cli-tools/concurrently?sponsor=1"
      }
    },
    "node_modules/content-disposition": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/content-disposition/-/content-disposition-1.0.1.tgz",
      "integrity": "sha512-oIXISMynqSqm241k6kcQ5UwttDILMK4BiurCfGEREw6+X9jkkpEe5T9FZaApyLGGOnFuyMWZpdolTXMtvEJ08Q==",
      "license": "MIT",
      "engines": {
        "node": ">=18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/content-type": {
      "version": "1.0.5",
      "resolved": "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz",
      "integrity": "sha512-nTjqfcBFEipKdXCv4YDQWCfmcLZKm81ldF0pAopTvyrFGVbcR6P/VAAd5G7N+0tTr8QqiU0tFadD6FK4NtJwOA==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/cookie": {
      "version": "0.7.2",
      "resolved": "https://registry.npmjs.org/cookie/-/cookie-0.7.2.tgz",
      "integrity": "sha512-yki5XnKuf750l50uGTllt6kKILY4nQ1eNIQatoXEByZ5dWgnKqbnqmTrBE5B4N7lrMJKQ2ytWMiTO2o0v6Ew/w==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/cookie-signature": {
      "version": "1.2.2",
      "resolved": "https://registry.npmjs.org/cookie-signature/-/cookie-signature-1.2.2.tgz",
      "integrity": "sha512-D76uU73ulSXrD1UXF4KE2TMxVVwhsnCgfAyTg9k8P6KGZjlXKrOLe4dJQKI3Bxi5wjesZoFXJWElNWBjPZMbhg==",
      "license": "MIT",
      "engines": {
        "node": ">=6.6.0"
      }
    },
    "node_modules/d3-array": {
      "version": "3.2.4",
      "resolved": "https://registry.npmjs.org/d3-array/-/d3-array-3.2.4.tgz",
      "integrity": "sha512-tdQAmyA18i4J7wprpYq8ClcxZy3SC31QMeByyCFyRt7BVHdREQZ5lpzoe5mFEYZUWe+oq8HBvk9JjpibyEV4Jg==",
      "license": "ISC",
      "dependencies": {
        "internmap": "1 - 2"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-color": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-color/-/d3-color-3.1.0.tgz",
      "integrity": "sha512-zg/chbXyeBtMQ1LbD/WSoW2DpC3I0mpmPdW+ynRTj/x2DAWYrIY7qeZIHidozwV24m4iavr15lNwIwLxRmOxhA==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-ease": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-ease/-/d3-ease-3.0.1.tgz",
      "integrity": "sha512-wR/XK3D3XcLIZwpbvQwQ5fK+8Ykds1ip7A2Txe0yxncXSdq1L9skcG7blcedkOX+ZcgxGAmLX1FrRGbADwzi0w==",
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-format": {
      "version": "3.1.2",
      "resolved": "https://registry.npmjs.org/d3-format/-/d3-format-3.1.2.tgz",
      "integrity": "sha512-AJDdYOdnyRDV5b6ArilzCPPwc1ejkHcoyFarqlPqT7zRYjhavcT3uSrqcMvsgh2CgoPbK3RCwyHaVyxYcP2Arg==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-interpolate": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-interpolate/-/d3-interpolate-3.0.1.tgz",
      "integrity": "sha512-3bYs1rOD33uo8aqJfKP3JWPAibgw8Zm2+L9vBKEHJ2Rg+viTR7o5Mmv5mZcieN+FRYaAOWX5SJATX6k1PWz72g==",
      "license": "ISC",
      "dependencies": {
        "d3-color": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-path": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-path/-/d3-path-3.1.0.tgz",
      "integrity": "sha512-p3KP5HCf/bvjBSSKuXid6Zqijx7wIfNW+J/maPs+iwR35at5JCbLUT0LzF1cnjbCHWhqzQTIN2Jpe8pRebIEFQ==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-scale": {
      "version": "4.0.2",
      "resolved": "https://registry.npmjs.org/d3-scale/-/d3-scale-4.0.2.tgz",
      "integrity": "sha512-GZW464g1SH7ag3Y7hXjf8RoUuAFIqklOAq3MRl4OaWabTFJY9PN/E1YklhXLh+OQ3fM9yS2nOkCoS+WLZ6kvxQ==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "2.10.0 - 3",
        "d3-format": "1 - 3",
        "d3-interpolate": "1.2.0 - 3",
        "d3-time": "2.1.1 - 3",
        "d3-time-format": "2 - 4"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-shape": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/d3-shape/-/d3-shape-3.2.0.tgz",
      "integrity": "sha512-SaLBuwGm3MOViRq2ABk3eLoxwZELpH6zhl3FbAoJ7Vm1gofKx6El1Ib5z23NUEhF9AsGl7y+dzLe5Cw2AArGTA==",
      "license": "ISC",
      "dependencies": {
        "d3-path": "^3.1.0"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-time": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-time/-/d3-time-3.1.0.tgz",
      "integrity": "sha512-VqKjzBLejbSMT4IgbmVgDjpkYrNWUYJnbCGo874u7MMKIWsILRX+OpX/gTk8MqjpT1A/c6HY2dCA77ZN0lkQ2Q==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "2 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-time-format": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/d3-time-format/-/d3-time-format-4.1.0.tgz",
      "integrity": "sha512-dJxPBlzC7NugB2PDLwo9Q8JiTR3M3e4/XANkreKSUxF8vvXKqm1Yfq4Q5dl8budlunRVlUUaDUgFt7eA8D6NLg==",
      "license": "ISC",
      "dependencies": {
        "d3-time": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-timer": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-timer/-/d3-timer-3.0.1.tgz",
      "integrity": "sha512-ndfJ/JxxMd3nw31uyKoY2naivF+r29V+Lc0svZxe1JvvIRmi8hUsrMvdOwgS1o6uBHmiz91geQ0ylPP0aj1VUA==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/debug": {
      "version": "4.4.3",
      "resolved": "https://registry.npmjs.org/debug/-/debug-4.4.3.tgz",
      "integrity": "sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==",
      "license": "MIT",
      "dependencies": {
        "ms": "^2.1.3"
      },
      "engines": {
        "node": ">=6.0"
      },
      "peerDependenciesMeta": {
        "supports-color": {
          "optional": true
        }
      }
    },
    "node_modules/decimal.js-light": {
      "version": "2.5.1",
      "resolved": "https://registry.npmjs.org/decimal.js-light/-/decimal.js-light-2.5.1.tgz",
      "integrity": "sha512-qIMFpTMZmny+MMIitAB6D7iVPEorVw6YQRWkvarTkT4tBeSLLiHzcwj6q0MmYSFCiVpiqPJTJEYIrpcPzVEIvg==",
      "license": "MIT"
    },
    "node_modules/decompress-response": {
      "version": "6.0.0",
      "resolved": "https://registry.npmjs.org/decompress-response/-/decompress-response-6.0.0.tgz",
      "integrity": "sha512-aW35yZM6Bb/4oJlZncMH2LCoZtJXTRxES17vE3hoRiowU2kWHaJKFkSBDnDR+cm9J+9QhXmREyIfv0pji9ejCQ==",
      "license": "MIT",
      "dependencies": {
        "mimic-response": "^3.1.0"
      },
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/deep-extend": {
      "version": "0.6.0",
      "resolved": "https://registry.npmjs.org/deep-extend/-/deep-extend-0.6.0.tgz",
      "integrity": "sha512-LOHxIOaPYdHlJRtCQfDIVZtfw/ufM8+rVj649RIHzcm/vGwQRXFt6OPqIFWsm2XEMrNIEtWR64sY1LEKD2vAOA==",
      "license": "MIT",
      "engines": {
        "node": ">=4.0.0"
      }
    },
    "node_modules/depd": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/depd/-/depd-2.0.0.tgz",
      "integrity": "sha512-g7nH6P6dyDioJogAAGprGpCtVImJhpPk/roCzdb3fIh61/s/nPsfR6onyMwkCAR/OlC3yBC0lESvUoQEAssIrw==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/detect-libc": {
      "version": "2.1.2",
      "resolved": "https://registry.npmjs.org/detect-libc/-/detect-libc-2.1.2.tgz",
      "integrity": "sha512-Btj2BOOO83o3WyH59e8MgXsxEQVcarkUOpEYrubB0urwnN10yQ364rsiByU11nZlqWYZm05i/of7io4mzihBtQ==",
      "license": "Apache-2.0",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/dexie": {
      "version": "4.3.0",
      "resolved": "https://registry.npmjs.org/dexie/-/dexie-4.3.0.tgz",
      "integrity": "sha512-5EeoQpJvMKHe6zWt/FSIIuRa3CWlZeIl6zKXt+Lz7BU6RoRRLgX9dZEynRfXrkLcldKYCBiz7xekTEylnie1Ug==",
      "license": "Apache-2.0"
    },
    "node_modules/dunder-proto": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/dunder-proto/-/dunder-proto-1.0.1.tgz",
      "integrity": "sha512-KIN/nDJBQRcXw0MLVhZE9iQHmG68qAVIBg9CqmUYjmQIhgij9U5MFvrqkUL5FbtyyzZuOeOt0zdeRe4UY7ct+A==",
      "license": "MIT",
      "dependencies": {
        "call-bind-apply-helpers": "^1.0.1",
        "es-errors": "^1.3.0",
        "gopd": "^1.2.0"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/ecdsa-sig-formatter": {
      "version": "1.0.11",
      "resolved": "https://registry.npmjs.org/ecdsa-sig-formatter/-/ecdsa-sig-formatter-1.0.11.tgz",
      "integrity": "sha512-nagl3RYrbNv6kQkeJIpt6NJZy8twLB/2vtz6yN9Z4vRKHN4/QZJIEbqohALSgwKdnksuY3k5Addp5lg8sVoVcQ==",
      "license": "Apache-2.0",
      "dependencies": {
        "safe-buffer": "^5.0.1"
      }
    },
    "node_modules/ee-first": {
      "version": "1.1.1",
      "resolved": "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz",
      "integrity": "sha512-WMwm9LhRUo+WUaRN+vRuETqG89IgZphVSNkdFgeb6sS/E4OrDIN7t48CAewSHXc6C8lefD8KKfr5vY61brQlow==",
      "license": "MIT"
    },
    "node_modules/emoji-regex": {
      "version": "8.0.0",
      "resolved": "https://registry.npmjs.org/emoji-regex/-/emoji-regex-8.0.0.tgz",
      "integrity": "sha512-MSjYzcWNOA0ewAHpz0MxpYFvwg6yjy1NG3xteoqz644VCo/RPgnr1/GGt+ic3iJTzQ8Eu3TdM14SawnVUmGE6A==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/encodeurl": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/encodeurl/-/encodeurl-2.0.0.tgz",
      "integrity": "sha512-Q0n9HRi4m6JuGIV1eFlmvJB7ZEVxu93IrMyiMsGC0lrMJMWzRgx6WGquyfQgZVb31vhGgXnfmPNNXmxnOkRBrg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/end-of-stream": {
      "version": "1.4.5",
      "resolved": "https://registry.npmjs.org/end-of-stream/-/end-of-stream-1.4.5.tgz",
      "integrity": "sha512-ooEGc6HP26xXq/N+GCGOT0JKCLDGrq2bQUZrQ7gyrJiZANJ/8YDTxTpQBXGMn+WbIQXNVpyWymm7KYVICQnyOg==",
      "license": "MIT",
      "dependencies": {
        "once": "^1.4.0"
      }
    },
    "node_modules/es-define-property": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/es-define-property/-/es-define-property-1.0.1.tgz",
      "integrity": "sha512-e3nRfgfUZ4rNGL232gUgX06QNyyez04KdjFrF+LTRoOXmrOgFKDg4BCdsjW8EnT69eqdYGmRpJwiPVYNrCaW3g==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/es-errors": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/es-errors/-/es-errors-1.3.0.tgz",
      "integrity": "sha512-Zf5H2Kxt2xjTvbJvP2ZWLEICxA6j+hAmMzIlypy4xcBg1vKVnx89Wy0GbS+kf5cwCVFFzdCFh2XSCFNULS6csw==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/es-object-atoms": {
      "version": "1.1.1",
      "resolved": "https://registry.npmjs.org/es-object-atoms/-/es-object-atoms-1.1.1.tgz",
      "integrity": "sha512-FGgH2h8zKNim9ljj7dankFPcICIK9Cp5bm+c2gQSYePhpaG5+esrLODihIorn+Pe6FGJzWhXQotPv73jTaldXA==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/es-toolkit": {
      "version": "1.45.1",
      "resolved": "https://registry.npmjs.org/es-toolkit/-/es-toolkit-1.45.1.tgz",
      "integrity": "sha512-/jhoOj/Fx+A+IIyDNOvO3TItGmlMKhtX8ISAHKE90c4b/k1tqaqEZ+uUqfpU8DMnW5cgNJv606zS55jGvza0Xw==",
      "license": "MIT",
      "workspaces": [
        "docs",
        "benchmarks"
      ]
    },
    "node_modules/esbuild": {
      "version": "0.25.6",
      "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.25.6.tgz",
      "integrity": "sha512-GVuzuUwtdsghE3ocJ9Bs8PNoF13HNQ5TXbEi2AhvVb8xU1Iwt9Fos9FEamfoee+u/TOsn7GUWc04lz46n2bbTg==",
      "dev": true,
      "hasInstallScript": true,
      "license": "MIT",
      "bin": {
        "esbuild": "bin/esbuild"
      },
      "engines": {
        "node": ">=18"
      },
      "optionalDependencies": {
        "@esbuild/aix-ppc64": "0.25.6",
        "@esbuild/android-arm": "0.25.6",
        "@esbuild/android-arm64": "0.25.6",
        "@esbuild/android-x64": "0.25.6",
        "@esbuild/darwin-arm64": "0.25.6",
        "@esbuild/darwin-x64": "0.25.6",
        "@esbuild/freebsd-arm64": "0.25.6",
        "@esbuild/freebsd-x64": "0.25.6",
        "@esbuild/linux-arm": "0.25.6",
        "@esbuild/linux-arm64": "0.25.6",
        "@esbuild/linux-ia32": "0.25.6",
        "@esbuild/linux-loong64": "0.25.6",
        "@esbuild/linux-mips64el": "0.25.6",
        "@esbuild/linux-ppc64": "0.25.6",
        "@esbuild/linux-riscv64": "0.25.6",
        "@esbuild/linux-s390x": "0.25.6",
        "@esbuild/linux-x64": "0.25.6",
        "@esbuild/netbsd-arm64": "0.25.6",
        "@esbuild/netbsd-x64": "0.25.6",
        "@esbuild/openbsd-arm64": "0.25.6",
        "@esbuild/openbsd-x64": "0.25.6",
        "@esbuild/openharmony-arm64": "0.25.6",
        "@esbuild/sunos-x64": "0.25.6",
        "@esbuild/win32-arm64": "0.25.6",
        "@esbuild/win32-ia32": "0.25.6",
        "@esbuild/win32-x64": "0.25.6"
      }
    },
    "node_modules/escalade": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/escalade/-/escalade-3.2.0.tgz",
      "integrity": "sha512-WUj2qlxaQtO4g6Pq5c29GTcWGDyd8itL8zTlipgECz3JesAiiOKotd8JU6otB3PACgG6xkJUyVhboMS+bje/jA==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/escape-html": {
      "version": "1.0.3",
      "resolved": "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz",
      "integrity": "sha512-NiSupZ4OeuGwr68lGIeym/ksIZMJodUGOSCZ/FSnTxcrekbvqrgdUxlJOMpijaKZVjAJrWrGs/6Jy8OMuyj9ow==",
      "license": "MIT"
    },
    "node_modules/etag": {
      "version": "1.8.1",
      "resolved": "https://registry.npmjs.org/etag/-/etag-1.8.1.tgz",
      "integrity": "sha512-aIL5Fx7mawVa300al2BnEE4iNvo1qETxLrPI/o05L7z6go7fCw1J6EQmbK4FmJ2AS7kgVF/KEZWufBfdClMcPg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/eventemitter3": {
      "version": "5.0.4",
      "resolved": "https://registry.npmjs.org/eventemitter3/-/eventemitter3-5.0.4.tgz",
      "integrity": "sha512-mlsTRyGaPBjPedk6Bvw+aqbsXDtoAyAzm5MO7JgU+yVRyMQ5O8bD4Kcci7BS85f93veegeCPkL8R4GLClnjLFw==",
      "license": "MIT"
    },
    "node_modules/expand-template": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/expand-template/-/expand-template-2.0.3.tgz",
      "integrity": "sha512-XYfuKMvj4O35f/pOXLObndIRvyQ+/+6AhODh+OKWj9S9498pHHn/IMszH+gt0fBCRWMNfk1ZSp5x3AifmnI2vg==",
      "license": "(MIT OR WTFPL)",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/express": {
      "version": "5.2.1",
      "resolved": "https://registry.npmjs.org/express/-/express-5.2.1.tgz",
      "integrity": "sha512-hIS4idWWai69NezIdRt2xFVofaF4j+6INOpJlVOLDO8zXGpUVEVzIYk12UUi2JzjEzWL3IOAxcTubgz9Po0yXw==",
      "license": "MIT",
      "dependencies": {
        "accepts": "^2.0.0",
        "body-parser": "^2.2.1",
        "content-disposition": "^1.0.0",
        "content-type": "^1.0.5",
        "cookie": "^0.7.1",
        "cookie-signature": "^1.2.1",
        "debug": "^4.4.0",
        "depd": "^2.0.0",
        "encodeurl": "^2.0.0",
        "escape-html": "^1.0.3",
        "etag": "^1.8.1",
        "finalhandler": "^2.1.0",
        "fresh": "^2.0.0",
        "http-errors": "^2.0.0",
        "merge-descriptors": "^2.0.0",
        "mime-types": "^3.0.0",
        "on-finished": "^2.4.1",
        "once": "^1.4.0",
        "parseurl": "^1.3.3",
        "proxy-addr": "^2.0.7",
        "qs": "^6.14.0",
        "range-parser": "^1.2.1",
        "router": "^2.2.0",
        "send": "^1.1.0",
        "serve-static": "^2.2.0",
        "statuses": "^2.0.1",
        "type-is": "^2.0.1",
        "vary": "^1.1.2"
      },
      "engines": {
        "node": ">= 18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/extend": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/extend/-/extend-3.0.2.tgz",
      "integrity": "sha512-fjquC59cD7CyW6urNXK0FBufkZcoiGG80wTuPujX590cB5Ttln20E2UB4S/WARVqhXffZl2LNgS+gQdPIIim/g==",
      "license": "MIT"
    },
    "node_modules/fdir": {
      "version": "6.4.6",
      "resolved": "https://registry.npmjs.org/fdir/-/fdir-6.4.6.tgz",
      "integrity": "sha512-hiFoqpyZcfNm1yc4u8oWCf9A2c4D3QjCrks3zmoVKVxpQRzmPNar1hUJcBG2RQHvEVGDN+Jm81ZheVLAQMK6+w==",
      "dev": true,
      "license": "MIT",
      "peerDependencies": {
        "picomatch": "^3 || ^4"
      },
      "peerDependenciesMeta": {
        "picomatch": {
          "optional": true
        }
      }
    },
    "node_modules/file-uri-to-path": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/file-uri-to-path/-/file-uri-to-path-1.0.0.tgz",
      "integrity": "sha512-0Zt+s3L7Vf1biwWZ29aARiVYLx7iMGnEUl9x33fbB/j3jR81u/O2LbqK+Bm1CDSNDKVtJ/YjwY7TUd5SkeLQLw==",
      "license": "MIT"
    },
    "node_modules/finalhandler": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/finalhandler/-/finalhandler-2.1.1.tgz",
      "integrity": "sha512-S8KoZgRZN+a5rNwqTxlZZePjT/4cnm0ROV70LedRHZ0p8u9fRID0hJUZQpkKLzro8LfmC8sx23bY6tVNxv8pQA==",
      "license": "MIT",
      "dependencies": {
        "debug": "^4.4.0",
        "encodeurl": "^2.0.0",
        "escape-html": "^1.0.3",
        "on-finished": "^2.4.1",
        "parseurl": "^1.3.3",
        "statuses": "^2.0.1"
      },
      "engines": {
        "node": ">= 18.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/forwarded": {
      "version": "0.2.0",
      "resolved": "https://registry.npmjs.org/forwarded/-/forwarded-0.2.0.tgz",
      "integrity": "sha512-buRG0fpBtRHSTCOASe6hD258tEubFoRLb4ZNA6NxMVHNw2gOcwHo9wyablzMzOA5z9xA9L1KNjk/Nt6MT9aYow==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/fresh": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/fresh/-/fresh-2.0.0.tgz",
      "integrity": "sha512-Rx/WycZ60HOaqLKAi6cHRKKI7zxWbJ31MhntmtwMoaTeF7XFH9hhBp8vITaMidfljRQ6eYWCKkaTK+ykVJHP2A==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/fs-constants": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/fs-constants/-/fs-constants-1.0.0.tgz",
      "integrity": "sha512-y6OAwoSIf7FyjMIv94u+b5rdheZEjzR63GTyZJm5qh4Bi+2YgwLCcI/fPFZkL5PSixOt6ZNKm+w+Hfp/Bciwow==",
      "license": "MIT"
    },
    "node_modules/fsevents": {
      "version": "2.3.3",
      "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
      "integrity": "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==",
      "dev": true,
      "hasInstallScript": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": "^8.16.0 || ^10.6.0 || >=11.0.0"
      }
    },
    "node_modules/function-bind": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/function-bind/-/function-bind-1.1.2.tgz",
      "integrity": "sha512-7XHNxH7qX9xG5mIwxkhumTox/MIRNcOgDrxWsMt2pAr23WHp6MrRlN7FBSFpCpr+oVO0F744iUgR82nJMfG2SA==",
      "license": "MIT",
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/gaxios": {
      "version": "6.7.1",
      "resolved": "https://registry.npmjs.org/gaxios/-/gaxios-6.7.1.tgz",
      "integrity": "sha512-LDODD4TMYx7XXdpwxAVRAIAuB0bzv0s+ywFonY46k126qzQHT9ygyoa9tncmOiQmmDrik65UYsEkv3lbfqQ3yQ==",
      "license": "Apache-2.0",
      "dependencies": {
        "extend": "^3.0.2",
        "https-proxy-agent": "^7.0.1",
        "is-stream": "^2.0.0",
        "node-fetch": "^2.6.9",
        "uuid": "^9.0.1"
      },
      "engines": {
        "node": ">=14"
      }
    },
    "node_modules/gcp-metadata": {
      "version": "6.1.1",
      "resolved": "https://registry.npmjs.org/gcp-metadata/-/gcp-metadata-6.1.1.tgz",
      "integrity": "sha512-a4tiq7E0/5fTjxPAaH4jpjkSv/uCaU2p5KC6HVGrvl0cDjA8iBZv4vv1gyzlmK0ZUKqwpOyQMKzZQe3lTit77A==",
      "license": "Apache-2.0",
      "dependencies": {
        "gaxios": "^6.1.1",
        "google-logging-utils": "^0.0.2",
        "json-bigint": "^1.0.0"
      },
      "engines": {
        "node": ">=14"
      }
    },
    "node_modules/get-caller-file": {
      "version": "2.0.5",
      "resolved": "https://registry.npmjs.org/get-caller-file/-/get-caller-file-2.0.5.tgz",
      "integrity": "sha512-DyFP3BM/3YHTQOCUL/w0OZHR0lpKeGrxotcHWcqNEdnltqFwXVfhEBQ94eIo34AfQpo0rGki4cyIiftY06h2Fg==",
      "dev": true,
      "license": "ISC",
      "engines": {
        "node": "6.* || 8.* || >= 10.*"
      }
    },
    "node_modules/get-intrinsic": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/get-intrinsic/-/get-intrinsic-1.3.0.tgz",
      "integrity": "sha512-9fSjSaos/fRIVIp+xSJlE6lfwhES7LNtKaCBIamHsjr2na1BiABJPo0mOjjz8GJDURarmCPGqaiVg5mfjb98CQ==",
      "license": "MIT",
      "dependencies": {
        "call-bind-apply-helpers": "^1.0.2",
        "es-define-property": "^1.0.1",
        "es-errors": "^1.3.0",
        "es-object-atoms": "^1.1.1",
        "function-bind": "^1.1.2",
        "get-proto": "^1.0.1",
        "gopd": "^1.2.0",
        "has-symbols": "^1.1.0",
        "hasown": "^2.0.2",
        "math-intrinsics": "^1.1.0"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/get-proto": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/get-proto/-/get-proto-1.0.1.tgz",
      "integrity": "sha512-sTSfBjoXBp89JvIKIefqw7U2CCebsc74kiY6awiGogKtoSGbgjYE/G/+l9sF3MWFPNc9IcoOC4ODfKHfxFmp0g==",
      "license": "MIT",
      "dependencies": {
        "dunder-proto": "^1.0.1",
        "es-object-atoms": "^1.0.0"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/get-tsconfig": {
      "version": "4.13.6",
      "resolved": "https://registry.npmjs.org/get-tsconfig/-/get-tsconfig-4.13.6.tgz",
      "integrity": "sha512-shZT/QMiSHc/YBLxxOkMtgSid5HFoauqCE3/exfsEcwg1WkeqjG+V40yBbBrsD+jW2HDXcs28xOfcbm2jI8Ddw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "resolve-pkg-maps": "^1.0.0"
      },
      "funding": {
        "url": "https://github.com/privatenumber/get-tsconfig?sponsor=1"
      }
    },
    "node_modules/github-from-package": {
      "version": "0.0.0",
      "resolved": "https://registry.npmjs.org/github-from-package/-/github-from-package-0.0.0.tgz",
      "integrity": "sha512-SyHy3T1v2NUXn29OsWdxmK6RwHD+vkj3v8en8AOBZ1wBQ/hCAQ5bAQTD02kW4W9tUp/3Qh6J8r9EvntiyCmOOw==",
      "license": "MIT"
    },
    "node_modules/google-auth-library": {
      "version": "9.15.1",
      "resolved": "https://registry.npmjs.org/google-auth-library/-/google-auth-library-9.15.1.tgz",
      "integrity": "sha512-Jb6Z0+nvECVz+2lzSMt9u98UsoakXxA2HGHMCxh+so3n90XgYWkq5dur19JAJV7ONiJY22yBTyJB1TSkvPq9Ng==",
      "license": "Apache-2.0",
      "dependencies": {
        "base64-js": "^1.3.0",
        "ecdsa-sig-formatter": "^1.0.11",
        "gaxios": "^6.1.1",
        "gcp-metadata": "^6.1.0",
        "gtoken": "^7.0.0",
        "jws": "^4.0.0"
      },
      "engines": {
        "node": ">=14"
      }
    },
    "node_modules/google-logging-utils": {
      "version": "0.0.2",
      "resolved": "https://registry.npmjs.org/google-logging-utils/-/google-logging-utils-0.0.2.tgz",
      "integrity": "sha512-NEgUnEcBiP5HrPzufUkBzJOD/Sxsco3rLNo1F1TNf7ieU8ryUzBhqba8r756CjLX7rn3fHl6iLEwPYuqpoKgQQ==",
      "license": "Apache-2.0",
      "engines": {
        "node": ">=14"
      }
    },
    "node_modules/gopd": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/gopd/-/gopd-1.2.0.tgz",
      "integrity": "sha512-ZUKRh6/kUFoAiTAtTYPZJ3hw9wNxx+BIBOijnlG9PnrJsCcSjs1wyyD6vJpaYtgnzDrKYRSqf3OO6Rfa93xsRg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/gtoken": {
      "version": "7.1.0",
      "resolved": "https://registry.npmjs.org/gtoken/-/gtoken-7.1.0.tgz",
      "integrity": "sha512-pCcEwRi+TKpMlxAQObHDQ56KawURgyAf6jtIY046fJ5tIv3zDe/LEIubckAO8fj6JnAxLdmWkUfNyulQ2iKdEw==",
      "license": "MIT",
      "dependencies": {
        "gaxios": "^6.0.0",
        "jws": "^4.0.0"
      },
      "engines": {
        "node": ">=14.0.0"
      }
    },
    "node_modules/has-flag": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/has-flag/-/has-flag-4.0.0.tgz",
      "integrity": "sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/has-symbols": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/has-symbols/-/has-symbols-1.1.0.tgz",
      "integrity": "sha512-1cDNdwJ2Jaohmb3sg4OmKaMBwuC48sYni5HUw2DvsC8LjGTLK9h+eb1X6RyuOHe4hT0ULCW68iomhjUoKUqlPQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/hasown": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/hasown/-/hasown-2.0.2.tgz",
      "integrity": "sha512-0hJU9SCPvmMzIBdZFqNPXWa6dqh7WdH0cII9y+CyS8rG3nL48Bclra9HmKhVVUHyPWNH5Y7xDwAB7bfgSjkUMQ==",
      "license": "MIT",
      "dependencies": {
        "function-bind": "^1.1.2"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/http-errors": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/http-errors/-/http-errors-2.0.1.tgz",
      "integrity": "sha512-4FbRdAX+bSdmo4AUFuS0WNiPz8NgFt+r8ThgNWmlrjQjt1Q7ZR9+zTlce2859x4KSXrwIsaeTqDoKQmtP8pLmQ==",
      "license": "MIT",
      "dependencies": {
        "depd": "~2.0.0",
        "inherits": "~2.0.4",
        "setprototypeof": "~1.2.0",
        "statuses": "~2.0.2",
        "toidentifier": "~1.0.1"
      },
      "engines": {
        "node": ">= 0.8"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/https-proxy-agent": {
      "version": "7.0.6",
      "resolved": "https://registry.npmjs.org/https-proxy-agent/-/https-proxy-agent-7.0.6.tgz",
      "integrity": "sha512-vK9P5/iUfdl95AI+JVyUuIcVtd4ofvtrOr3HNtM2yxC9bnMbEdp3x01OhQNnjb8IJYi38VlTE3mBXwcfvywuSw==",
      "license": "MIT",
      "dependencies": {
        "agent-base": "^7.1.2",
        "debug": "4"
      },
      "engines": {
        "node": ">= 14"
      }
    },
    "node_modules/iconv-lite": {
      "version": "0.7.2",
      "resolved": "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.7.2.tgz",
      "integrity": "sha512-im9DjEDQ55s9fL4EYzOAv0yMqmMBSZp6G0VvFyTMPKWxiSBHUj9NW/qqLmXUwXrrM7AvqSlTCfvqRb0cM8yYqw==",
      "license": "MIT",
      "dependencies": {
        "safer-buffer": ">= 2.1.2 < 3.0.0"
      },
      "engines": {
        "node": ">=0.10.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/ieee754": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/ieee754/-/ieee754-1.2.1.tgz",
      "integrity": "sha512-dcyqhDvX1C46lXZcVqCpK+FtMRQVdIMN6/Df5js2zouUsqG7I6sFxitIC+7KYK29KdXOLHdu9zL4sFnoVQnqaA==",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "BSD-3-Clause"
    },
    "node_modules/immer": {
      "version": "10.2.0",
      "resolved": "https://registry.npmjs.org/immer/-/immer-10.2.0.tgz",
      "integrity": "sha512-d/+XTN3zfODyjr89gM3mPq1WNX2B8pYsu7eORitdwyA2sBubnTl3laYlBk4sXY5FUa5qTZGBDPJICVbvqzjlbw==",
      "license": "MIT",
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/immer"
      }
    },
    "node_modules/inherits": {
      "version": "2.0.4",
      "resolved": "https://registry.npmjs.org/inherits/-/inherits-2.0.4.tgz",
      "integrity": "sha512-k/vGaX4/Yla3WzyMCvTQOXYeIHvqOKtnqBduzTHpzpQZzAskKMhZ2K+EnBiSM9zGSoIFeMpXKxa4dYeZIQqewQ==",
      "license": "ISC"
    },
    "node_modules/ini": {
      "version": "1.3.8",
      "resolved": "https://registry.npmjs.org/ini/-/ini-1.3.8.tgz",
      "integrity": "sha512-JV/yugV2uzW5iMRSiZAyDtQd+nxtUnjeLt0acNdw98kKLrvuRVyB80tsREOE7yvGVgalhZ6RNXCmEHkUKBKxew==",
      "license": "ISC"
    },
    "node_modules/internmap": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/internmap/-/internmap-2.0.3.tgz",
      "integrity": "sha512-5Hh7Y1wQbvY5ooGgPbDaL5iYLAPzMTUrjMulskHLH6wnv/A+1q5rgEaiuqEjB+oxGXIVZs1FF+R/KPN3ZSQYYg==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/ipaddr.js": {
      "version": "1.9.1",
      "resolved": "https://registry.npmjs.org/ipaddr.js/-/ipaddr.js-1.9.1.tgz",
      "integrity": "sha512-0KI/607xoxSToH7GjN1FfSbLoU0+btTicjsQSWQlh/hZykN8KpmMf7uYwPW3R+akZ6R/w18ZlXSHBYXiYUPO3g==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.10"
      }
    },
    "node_modules/is-fullwidth-code-point": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-3.0.0.tgz",
      "integrity": "sha512-zymm5+u+sCsSWyD9qNaejV3DFvhCKclKdizYaJUuHA83RLjb7nSuGnddCHGv0hk+KY7BMAlsWeK4Ueg6EV6XQg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/is-promise": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/is-promise/-/is-promise-4.0.0.tgz",
      "integrity": "sha512-hvpoI6korhJMnej285dSg6nu1+e6uxs7zG3BYAm5byqDsgJNWwxzM6z6iZiAgQR4TJ30JmBTOwqZUw3WlyH3AQ==",
      "license": "MIT"
    },
    "node_modules/is-stream": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/is-stream/-/is-stream-2.0.1.tgz",
      "integrity": "sha512-hFoiJiTl63nn+kstHGBtewWSKnQLpyb155KHheA1l39uvtO9nWIop1p3udqPcUd/xbF1VLMO4n7OI6p7RbngDg==",
      "license": "MIT",
      "engines": {
        "node": ">=8"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/json-bigint": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/json-bigint/-/json-bigint-1.0.0.tgz",
      "integrity": "sha512-SiPv/8VpZuWbvLSMtTDU8hEfrZWg/mH/nV/b4o0CYbSxu1UIQPLdwKOCIyLQX+VIPO5vrLX3i8qtqFyhdPSUSQ==",
      "license": "MIT",
      "dependencies": {
        "bignumber.js": "^9.0.0"
      }
    },
    "node_modules/jwa": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/jwa/-/jwa-2.0.1.tgz",
      "integrity": "sha512-hRF04fqJIP8Abbkq5NKGN0Bbr3JxlQ+qhZufXVr0DvujKy93ZCbXZMHDL4EOtodSbCWxOqR8MS1tXA5hwqCXDg==",
      "license": "MIT",
      "dependencies": {
        "buffer-equal-constant-time": "^1.0.1",
        "ecdsa-sig-formatter": "1.0.11",
        "safe-buffer": "^5.0.1"
      }
    },
    "node_modules/jws": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/jws/-/jws-4.0.0.tgz",
      "integrity": "sha512-KDncfTmOZoOMTFG4mBlG0qUIOlc03fmzH+ru6RgYVZhPkyiy/92Owlt/8UEN+a4TXR1FQetfIpJE8ApdvdVxTg==",
      "license": "MIT",
      "dependencies": {
        "jwa": "^2.0.0",
        "safe-buffer": "^5.0.1"
      }
    },
    "node_modules/lru-cache": {
      "version": "11.2.6",
      "resolved": "https://registry.npmjs.org/lru-cache/-/lru-cache-11.2.6.tgz",
      "integrity": "sha512-ESL2CrkS/2wTPfuend7Zhkzo2u0daGJ/A2VucJOgQ/C48S/zB8MMeMHSGKYpXhIjbPxfuezITkaBH1wqv00DDQ==",
      "license": "BlueOak-1.0.0",
      "engines": {
        "node": "20 || >=22"
      }
    },
    "node_modules/math-intrinsics": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/math-intrinsics/-/math-intrinsics-1.1.0.tgz",
      "integrity": "sha512-/IXtbwEk5HTPyEwyKX6hGkYXxM9nbj64B+ilVJnC/R6B0pH5G4V3b0pVbL7DBj4tkhBAppbQUlf6F6Xl9LHu1g==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/media-typer": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/media-typer/-/media-typer-1.1.0.tgz",
      "integrity": "sha512-aisnrDP4GNe06UcKFnV5bfMNPBUw4jsLGaWwWfnH3v02GnBuXX2MCVn5RbrWo0j3pczUilYblq7fQ7Nw2t5XKw==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/merge-descriptors": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/merge-descriptors/-/merge-descriptors-2.0.0.tgz",
      "integrity": "sha512-Snk314V5ayFLhp3fkUREub6WtjBfPdCPY1Ln8/8munuLuiYhsABgBVWsozAG+MWMbVEvcdcpbi9R7ww22l9Q3g==",
      "license": "MIT",
      "engines": {
        "node": ">=18"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/mime-db": {
      "version": "1.54.0",
      "resolved": "https://registry.npmjs.org/mime-db/-/mime-db-1.54.0.tgz",
      "integrity": "sha512-aU5EJuIN2WDemCcAp2vFBfp/m4EAhWJnUNSSw0ixs7/kXbd6Pg64EmwJkNdFhB8aWt1sH2CTXrLxo/iAGV3oPQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/mime-types": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/mime-types/-/mime-types-3.0.2.tgz",
      "integrity": "sha512-Lbgzdk0h4juoQ9fCKXW4by0UJqj+nOOrI9MJ1sSj4nI8aI2eo1qmvQEie4VD1glsS250n15LsWsYtCugiStS5A==",
      "license": "MIT",
      "dependencies": {
        "mime-db": "^1.54.0"
      },
      "engines": {
        "node": ">=18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/mimic-response": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/mimic-response/-/mimic-response-3.1.0.tgz",
      "integrity": "sha512-z0yWI+4FDrrweS8Zmt4Ej5HdJmky15+L2e6Wgn3+iK5fWzb6T3fhNFq2+MeTRb064c6Wr4N/wv0DzQTjNzHNGQ==",
      "license": "MIT",
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/minimist": {
      "version": "1.2.8",
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",
      "integrity": "sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==",
      "license": "MIT",
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/mkdirp-classic": {
      "version": "0.5.3",
      "resolved": "https://registry.npmjs.org/mkdirp-classic/-/mkdirp-classic-0.5.3.tgz",
      "integrity": "sha512-gKLcREMhtuZRwRAfqP3RFW+TK4JqApVBtOIftVgjuABpAtpxhPGaDcfvbhNvD0B8iD1oUr/txX35NjcaY6Ns/A==",
      "license": "MIT"
    },
    "node_modules/ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==",
      "license": "MIT"
    },
    "node_modules/multer": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/multer/-/multer-2.1.1.tgz",
      "integrity": "sha512-mo+QTzKlx8R7E5ylSXxWzGoXoZbOsRMpyitcht8By2KHvMbf3tjwosZ/Mu/XYU6UuJ3VZnODIrak5ZrPiPyB6A==",
      "license": "MIT",
      "dependencies": {
        "append-field": "^1.0.0",
        "busboy": "^1.6.0",
        "concat-stream": "^2.0.0",
        "type-is": "^1.6.18"
      },
      "engines": {
        "node": ">= 10.16.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/multer/node_modules/media-typer": {
      "version": "0.3.0",
      "resolved": "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz",
      "integrity": "sha512-dq+qelQ9akHpcOl/gUVRTxVIOkAJ1wR3QAvb4RsVjS8oVoFjDGTc679wJYmUmknUF5HwMLOgb5O+a3KxfWapPQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/multer/node_modules/mime-db": {
      "version": "1.52.0",
      "resolved": "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
      "integrity": "sha512-sPU4uV7dYlvtWJxwwxHD0PuihVNiE7TyAbQ5SWxDCB9mUYvOgroQOwYQQOKPJ8CIbE+1ETVlOoK1UC2nU3gYvg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/multer/node_modules/mime-types": {
      "version": "2.1.35",
      "resolved": "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
      "integrity": "sha512-ZDY+bPm5zTTF+YpCrAU9nK0UgICYPT0QtT1NZWFv4s++TNkcgVaT0g6+4R2uI4MjQjzysHB1zxuWL50hzaeXiw==",
      "license": "MIT",
      "dependencies": {
        "mime-db": "1.52.0"
      },
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/multer/node_modules/type-is": {
      "version": "1.6.18",
      "resolved": "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz",
      "integrity": "sha512-TkRKr9sUTxEH8MdfuCSP7VizJyzRNMjj2J2do2Jr3Kym598JVdEksuzPQCnlFPW4ky9Q+iA+ma9BGm06XQBy8g==",
      "license": "MIT",
      "dependencies": {
        "media-typer": "0.3.0",
        "mime-types": "~2.1.24"
      },
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/nan": {
      "version": "2.25.0",
      "resolved": "https://registry.npmjs.org/nan/-/nan-2.25.0.tgz",
      "integrity": "sha512-0M90Ag7Xn5KMLLZ7zliPWP3rT90P6PN+IzVFS0VqmnPktBk3700xUVv8Ikm9EUaUE5SDWdp/BIxdENzVznpm1g==",
      "license": "MIT"
    },
    "node_modules/nanoid": {
      "version": "3.3.11",
      "resolved": "https://registry.npmjs.org/nanoid/-/nanoid-3.3.11.tgz",
      "integrity": "sha512-N8SpfPUnUp1bK+PMYW8qSWdl9U+wwNWI4QKxOYDy9JAro3WMX7p2OeVRF9v+347pnakNevPmiHhNmZ2HbFA76w==",
      "dev": true,
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "MIT",
      "bin": {
        "nanoid": "bin/nanoid.cjs"
      },
      "engines": {
        "node": "^10 || ^12 || ^13.7 || ^14 || >=15.0.1"
      }
    },
    "node_modules/napi-build-utils": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/napi-build-utils/-/napi-build-utils-2.0.0.tgz",
      "integrity": "sha512-GEbrYkbfF7MoNaoh2iGG84Mnf/WZfB0GdGEsM8wz7Expx/LlWf5U8t9nvJKXSp3qr5IsEbK04cBGhol/KwOsWA==",
      "license": "MIT"
    },
    "node_modules/negotiator": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/negotiator/-/negotiator-1.0.0.tgz",
      "integrity": "sha512-8Ofs/AUQh8MaEcrlq5xOX0CQ9ypTF5dl78mjlMNfOK08fzpgTHQRQPBxcPlEtIw0yRpws+Zo/3r+5WRby7u3Gg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/node-abi": {
      "version": "3.88.0",
      "resolved": "https://registry.npmjs.org/node-abi/-/node-abi-3.88.0.tgz",
      "integrity": "sha512-At6b4UqIEVudaqPsXjmUO1r/N5BUr4yhDGs5PkBE8/oG5+TfLPhFechiskFsnT6Ql0VfUXbalUUCbfXxtj7K+w==",
      "license": "MIT",
      "dependencies": {
        "semver": "^7.3.5"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/node-fetch": {
      "version": "2.7.0",
      "resolved": "https://registry.npmjs.org/node-fetch/-/node-fetch-2.7.0.tgz",
      "integrity": "sha512-c4FRfUm/dbcWZ7U+1Wq0AwCyFL+3nt2bEw05wfxSz+DWpWsitgmSgYmy2dQdWyKC1694ELPqMs/YzUSNozLt8A==",
      "license": "MIT",
      "dependencies": {
        "whatwg-url": "^5.0.0"
      },
      "engines": {
        "node": "4.x || >=6.0.0"
      },
      "peerDependencies": {
        "encoding": "^0.1.0"
      },
      "peerDependenciesMeta": {
        "encoding": {
          "optional": true
        }
      }
    },
    "node_modules/object-inspect": {
      "version": "1.13.4",
      "resolved": "https://registry.npmjs.org/object-inspect/-/object-inspect-1.13.4.tgz",
      "integrity": "sha512-W67iLl4J2EXEGTbfeHCffrjDfitvLANg0UlX3wFUUSTx92KXRFegMHUVgSqE+wvhAbi4WqjGg9czysTV2Epbew==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/on-finished": {
      "version": "2.4.1",
      "resolved": "https://registry.npmjs.org/on-finished/-/on-finished-2.4.1.tgz",
      "integrity": "sha512-oVlzkg3ENAhCk2zdv7IJwd/QUD4z2RxRwpkcGY8psCVcCYZNq4wYnVWALHM+brtuJjePWiYF/ClmuDr8Ch5+kg==",
      "license": "MIT",
      "dependencies": {
        "ee-first": "1.1.1"
      },
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/once": {
      "version": "1.4.0",
      "resolved": "https://registry.npmjs.org/once/-/once-1.4.0.tgz",
      "integrity": "sha512-lNaJgI+2Q5URQBkccEKHTQOPaXdUxnZZElQTZY0MFUAuaEqe1E+Nyvgdz/aIyNi6Z9MzO5dv1H8n58/GELp3+w==",
      "license": "ISC",
      "dependencies": {
        "wrappy": "1"
      }
    },
    "node_modules/parseurl": {
      "version": "1.3.3",
      "resolved": "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz",
      "integrity": "sha512-CiyeOxFT/JZyN5m0z9PfXw4SCBJ6Sygz1Dpl0wqjlhDEGGBP1GnsUVEL0p63hoG1fcj3fHynXi9NYO4nWOL+qQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/path-to-regexp": {
      "version": "8.3.0",
      "resolved": "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-8.3.0.tgz",
      "integrity": "sha512-7jdwVIRtsP8MYpdXSwOS0YdD0Du+qOoF/AEPIt88PcCFrZCzx41oxku1jD88hZBwbNUIEfpqvuhjFaMAqMTWnA==",
      "license": "MIT",
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/pcap-parser": {
      "version": "0.2.1",
      "resolved": "https://registry.npmjs.org/pcap-parser/-/pcap-parser-0.2.1.tgz",
      "integrity": "sha512-+1t1GiMpEHI+MFub/mpCmfpyU4oVOyn4h71Zp5GqC/2uv0yteM6MghazKBQMkNXgmmsCPT1JUMfqsF03cYjnyw==",
      "license": "MIT",
      "engines": {
        "node": ">=0.6.0"
      }
    },
    "node_modules/pcap-writer": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/pcap-writer/-/pcap-writer-1.0.1.tgz",
      "integrity": "sha512-pDgJ7GlXeEnyzfNRRBCKN+DnA1F/lF8ti9bprnZTbC1Fpu7BYHHzOdB+Fj+TeGM3Tu7DkC+kX6eBNc0VFc+HBQ==",
      "license": "MIT",
      "dependencies": {
        "bufferpack": "0.0.6"
      }
    },
    "node_modules/picocolors": {
      "version": "1.1.1",
      "resolved": "https://registry.npmjs.org/picocolors/-/picocolors-1.1.1.tgz",
      "integrity": "sha512-xceH2snhtb5M9liqDsmEw56le376mTZkEX/jEb/RxNFyegNul7eNslCXP9FDj/Lcu0X8KEyMceP2ntpaHrDEVA==",
      "dev": true,
      "license": "ISC"
    },
    "node_modules/picomatch": {
      "version": "4.0.3",
      "resolved": "https://registry.npmjs.org/picomatch/-/picomatch-4.0.3.tgz",
      "integrity": "sha512-5gTmgEY/sqK6gFXLIsQNH19lWb4ebPDLA4SdLP7dsWkIXHWlG66oPuVvXSGFPppYZz8ZDZq0dYYrbHfBCVUb1Q==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=12"
      },
      "funding": {
        "url": "https://github.com/sponsors/jonschlinkert"
      }
    },
    "node_modules/postcss": {
      "version": "8.5.6",
      "resolved": "https://registry.npmjs.org/postcss/-/postcss-8.5.6.tgz",
      "integrity": "sha512-3Ybi1tAuwAP9s0r1UQ2J4n5Y0G05bJkpUIO0/bI9MhwmD70S5aTWbXGBwxHrelT+XM1k6dM0pk+SwNkpTRN7Pg==",
      "dev": true,
      "funding": [
        {
          "type": "opencollective",
          "url": "https://opencollective.com/postcss/"
        },
        {
          "type": "tidelift",
          "url": "https://tidelift.com/funding/github/npm/postcss"
        },
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "nanoid": "^3.3.11",
        "picocolors": "^1.1.1",
        "source-map-js": "^1.2.1"
      },
      "engines": {
        "node": "^10 || ^12 || >=14"
      }
    },
    "node_modules/prebuild-install": {
      "version": "7.1.3",
      "resolved": "https://registry.npmjs.org/prebuild-install/-/prebuild-install-7.1.3.tgz",
      "integrity": "sha512-8Mf2cbV7x1cXPUILADGI3wuhfqWvtiLA1iclTDbFRZkgRQS0NqsPZphna9V+HyTEadheuPmjaJMsbzKQFOzLug==",
      "deprecated": "No longer maintained. Please contact the author of the relevant native addon; alternatives are available.",
      "license": "MIT",
      "dependencies": {
        "detect-libc": "^2.0.0",
        "expand-template": "^2.0.3",
        "github-from-package": "0.0.0",
        "minimist": "^1.2.3",
        "mkdirp-classic": "^0.5.3",
        "napi-build-utils": "^2.0.0",
        "node-abi": "^3.3.0",
        "pump": "^3.0.0",
        "rc": "^1.2.7",
        "simple-get": "^4.0.0",
        "tar-fs": "^2.0.0",
        "tunnel-agent": "^0.6.0"
      },
      "bin": {
        "prebuild-install": "bin.js"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/proxy-addr": {
      "version": "2.0.7",
      "resolved": "https://registry.npmjs.org/proxy-addr/-/proxy-addr-2.0.7.tgz",
      "integrity": "sha512-llQsMLSUDUPT44jdrU/O37qlnifitDP+ZwrmmZcoSKyLKvtZxpyV0n2/bD/N4tBAAZ/gJEdZU7KMraoK1+XYAg==",
      "license": "MIT",
      "dependencies": {
        "forwarded": "0.2.0",
        "ipaddr.js": "1.9.1"
      },
      "engines": {
        "node": ">= 0.10"
      }
    },
    "node_modules/pump": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/pump/-/pump-3.0.4.tgz",
      "integrity": "sha512-VS7sjc6KR7e1ukRFhQSY5LM2uBWAUPiOPa/A3mkKmiMwSmRFUITt0xuj+/lesgnCv+dPIEYlkzrcyXgquIHMcA==",
      "license": "MIT",
      "dependencies": {
        "end-of-stream": "^1.1.0",
        "once": "^1.3.1"
      }
    },
    "node_modules/qs": {
      "version": "6.15.0",
      "resolved": "https://registry.npmjs.org/qs/-/qs-6.15.0.tgz",
      "integrity": "sha512-mAZTtNCeetKMH+pSjrb76NAM8V9a05I9aBZOHztWy/UqcJdQYNsf59vrRKWnojAT9Y+GbIvoTBC++CPHqpDBhQ==",
      "license": "BSD-3-Clause",
      "dependencies": {
        "side-channel": "^1.1.0"
      },
      "engines": {
        "node": ">=0.6"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/range-parser": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/range-parser/-/range-parser-1.2.1.tgz",
      "integrity": "sha512-Hrgsx+orqoygnmhFbKaHE6c296J+HTAQXoxEF6gNupROmmGJRoyzfG3ccAveqCBrwr/2yxQ5BVd/GTl5agOwSg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/raw-body": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/raw-body/-/raw-body-3.0.2.tgz",
      "integrity": "sha512-K5zQjDllxWkf7Z5xJdV0/B0WTNqx6vxG70zJE4N0kBs4LovmEYWJzQGxC9bS9RAKu3bgM40lrd5zoLJ12MQ5BA==",
      "license": "MIT",
      "dependencies": {
        "bytes": "~3.1.2",
        "http-errors": "~2.0.1",
        "iconv-lite": "~0.7.0",
        "unpipe": "~1.0.0"
      },
      "engines": {
        "node": ">= 0.10"
      }
    },
    "node_modules/rc": {
      "version": "1.2.8",
      "resolved": "https://registry.npmjs.org/rc/-/rc-1.2.8.tgz",
      "integrity": "sha512-y3bGgqKj3QBdxLbLkomlohkvsA8gdAiUQlSBJnBhfn+BPxg4bc62d8TcBW15wavDfgexCgccckhcZvywyQYPOw==",
      "license": "(BSD-2-Clause OR MIT OR Apache-2.0)",
      "dependencies": {
        "deep-extend": "^0.6.0",
        "ini": "~1.3.0",
        "minimist": "^1.2.0",
        "strip-json-comments": "~2.0.1"
      },
      "bin": {
        "rc": "cli.js"
      }
    },
    "node_modules/react": {
      "version": "19.1.0",
      "resolved": "https://registry.npmjs.org/react/-/react-19.1.0.tgz",
      "integrity": "sha512-FS+XFBNvn3GTAWq26joslQgWNoFu08F4kl0J4CgdNKADkdSGXQyTCnKteIAJy96Br6YbpEU1LSzV5dYtjMkMDg==",
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/react-dom": {
      "version": "19.1.0",
      "resolved": "https://registry.npmjs.org/react-dom/-/react-dom-19.1.0.tgz",
      "integrity": "sha512-Xs1hdnE+DyKgeHJeJznQmYMIBG3TKIHJJT95Q58nHLSrElKlGQqDTR2HQ9fx5CN/Gk6Vh/kupBTDLU11/nDk/g==",
      "license": "MIT",
      "dependencies": {
        "scheduler": "^0.26.0"
      },
      "peerDependencies": {
        "react": "^19.1.0"
      }
    },
    "node_modules/react-is": {
      "version": "19.2.4",
      "resolved": "https://registry.npmjs.org/react-is/-/react-is-19.2.4.tgz",
      "integrity": "sha512-W+EWGn2v0ApPKgKKCy/7s7WHXkboGcsrXE+2joLyVxkbyVQfO3MUEaUQDHoSmb8TFFrSKYa9mw64WZHNHSDzYA==",
      "license": "MIT",
      "peer": true
    },
    "node_modules/react-redux": {
      "version": "9.2.0",
      "resolved": "https://registry.npmjs.org/react-redux/-/react-redux-9.2.0.tgz",
      "integrity": "sha512-ROY9fvHhwOD9ySfrF0wmvu//bKCQ6AeZZq1nJNtbDC+kk5DuSuNX/n6YWYF/SYy7bSba4D4FSz8DJeKY/S/r+g==",
      "license": "MIT",
      "dependencies": {
        "@types/use-sync-external-store": "^0.0.6",
        "use-sync-external-store": "^1.4.0"
      },
      "peerDependencies": {
        "@types/react": "^18.2.25 || ^19",
        "react": "^18.0 || ^19",
        "redux": "^5.0.0"
      },
      "peerDependenciesMeta": {
        "@types/react": {
          "optional": true
        },
        "redux": {
          "optional": true
        }
      }
    },
    "node_modules/readable-stream": {
      "version": "3.6.2",
      "resolved": "https://registry.npmjs.org/readable-stream/-/readable-stream-3.6.2.tgz",
      "integrity": "sha512-9u/sniCrY3D5WdsERHzHE4G2YCXqoG5FTHUiCC4SIbr6XcLZBY05ya9EKjYek9O5xOAwjGq+1JdGBAS7Q9ScoA==",
      "license": "MIT",
      "dependencies": {
        "inherits": "^2.0.3",
        "string_decoder": "^1.1.1",
        "util-deprecate": "^1.0.1"
      },
      "engines": {
        "node": ">= 6"
      }
    },
    "node_modules/recharts": {
      "version": "3.8.0",
      "resolved": "https://registry.npmjs.org/recharts/-/recharts-3.8.0.tgz",
      "integrity": "sha512-Z/m38DX3L73ExO4Tpc9/iZWHmHnlzWG4njQbxsF5aSjwqmHNDDIm0rdEBArkwsBvR8U6EirlEHiQNYWCVh9sGQ==",
      "license": "MIT",
      "workspaces": [
        "www"
      ],
      "dependencies": {
        "@reduxjs/toolkit": "^1.9.0 || 2.x.x",
        "clsx": "^2.1.1",
        "decimal.js-light": "^2.5.1",
        "es-toolkit": "^1.39.3",
        "eventemitter3": "^5.0.1",
        "immer": "^10.1.1",
        "react-redux": "8.x.x || 9.x.x",
        "reselect": "5.1.1",
        "tiny-invariant": "^1.3.3",
        "use-sync-external-store": "^1.2.2",
        "victory-vendor": "^37.0.2"
      },
      "engines": {
        "node": ">=18"
      },
      "peerDependencies": {
        "react": "^16.8.0 || ^17.0.0 || ^18.0.0 || ^19.0.0",
        "react-dom": "^16.0.0 || ^17.0.0 || ^18.0.0 || ^19.0.0",
        "react-is": "^16.8.0 || ^17.0.0 || ^18.0.0 || ^19.0.0"
      }
    },
    "node_modules/redux": {
      "version": "5.0.1",
      "resolved": "https://registry.npmjs.org/redux/-/redux-5.0.1.tgz",
      "integrity": "sha512-M9/ELqF6fy8FwmkpnF0S3YKOqMyoWJ4+CS5Efg2ct3oY9daQvd/Pc71FpGZsVsbl3Cpb+IIcjBDUnnyBdQbq4w==",
      "license": "MIT"
    },
    "node_modules/redux-thunk": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/redux-thunk/-/redux-thunk-3.1.0.tgz",
      "integrity": "sha512-NW2r5T6ksUKXCabzhL9z+h206HQw/NJkcLm1GPImRQ8IzfXwRGqjVhKJGauHirT0DAuyy6hjdnMZaRoAcy0Klw==",
      "license": "MIT",
      "peerDependencies": {
        "redux": "^5.0.0"
      }
    },
    "node_modules/require-directory": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/require-directory/-/require-directory-2.1.1.tgz",
      "integrity": "sha512-fGxEI7+wsG9xrvdjsrlmL22OMTTiHRwAMroiEeMgq8gzoLC/PQr7RsRDSTLUg/bZAZtF+TVIkHc6/4RIKrui+Q==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/reselect": {
      "version": "5.1.1",
      "resolved": "https://registry.npmjs.org/reselect/-/reselect-5.1.1.tgz",
      "integrity": "sha512-K/BG6eIky/SBpzfHZv/dd+9JBFiS4SWV7FIujVyJRux6e45+73RaUHXLmIR1f7WOMaQ0U1km6qwklRQxpJJY0w==",
      "license": "MIT"
    },
    "node_modules/resolve-pkg-maps": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/resolve-pkg-maps/-/resolve-pkg-maps-1.0.0.tgz",
      "integrity": "sha512-seS2Tj26TBVOC2NIc2rOe2y2ZO7efxITtLZcGSOnHHNOQ7CkiUBfw0Iw2ck6xkIhPwLhKNLS8BO+hEpngQlqzw==",
      "dev": true,
      "license": "MIT",
      "funding": {
        "url": "https://github.com/privatenumber/resolve-pkg-maps?sponsor=1"
      }
    },
    "node_modules/rollup": {
      "version": "4.45.1",
      "resolved": "https://registry.npmjs.org/rollup/-/rollup-4.45.1.tgz",
      "integrity": "sha512-4iya7Jb76fVpQyLoiVpzUrsjQ12r3dM7fIVz+4NwoYvZOShknRmiv+iu9CClZml5ZLGb0XMcYLutK6w9tgxHDw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/estree": "1.0.8"
      },
      "bin": {
        "rollup": "dist/bin/rollup"
      },
      "engines": {
        "node": ">=18.0.0",
        "npm": ">=8.0.0"
      },
      "optionalDependencies": {
        "@rollup/rollup-android-arm-eabi": "4.45.1",
        "@rollup/rollup-android-arm64": "4.45.1",
        "@rollup/rollup-darwin-arm64": "4.45.1",
        "@rollup/rollup-darwin-x64": "4.45.1",
        "@rollup/rollup-freebsd-arm64": "4.45.1",
        "@rollup/rollup-freebsd-x64": "4.45.1",
        "@rollup/rollup-linux-arm-gnueabihf": "4.45.1",
        "@rollup/rollup-linux-arm-musleabihf": "4.45.1",
        "@rollup/rollup-linux-arm64-gnu": "4.45.1",
        "@rollup/rollup-linux-arm64-musl": "4.45.1",
        "@rollup/rollup-linux-loongarch64-gnu": "4.45.1",
        "@rollup/rollup-linux-powerpc64le-gnu": "4.45.1",
        "@rollup/rollup-linux-riscv64-gnu": "4.45.1",
        "@rollup/rollup-linux-riscv64-musl": "4.45.1",
        "@rollup/rollup-linux-s390x-gnu": "4.45.1",
        "@rollup/rollup-linux-x64-gnu": "4.45.1",
        "@rollup/rollup-linux-x64-musl": "4.45.1",
        "@rollup/rollup-win32-arm64-msvc": "4.45.1",
        "@rollup/rollup-win32-ia32-msvc": "4.45.1",
        "@rollup/rollup-win32-x64-msvc": "4.45.1",
        "fsevents": "~2.3.2"
      }
    },
    "node_modules/router": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/router/-/router-2.2.0.tgz",
      "integrity": "sha512-nLTrUKm2UyiL7rlhapu/Zl45FwNgkZGaCpZbIHajDYgwlJCOzLSk+cIPAnsEqV955GjILJnKbdQC1nVPz+gAYQ==",
      "license": "MIT",
      "dependencies": {
        "debug": "^4.4.0",
        "depd": "^2.0.0",
        "is-promise": "^4.0.0",
        "parseurl": "^1.3.3",
        "path-to-regexp": "^8.0.0"
      },
      "engines": {
        "node": ">= 18"
      }
    },
    "node_modules/rxjs": {
      "version": "7.8.2",
      "resolved": "https://registry.npmjs.org/rxjs/-/rxjs-7.8.2.tgz",
      "integrity": "sha512-dhKf903U/PQZY6boNNtAGdWbG85WAbjT/1xYoZIC7FAY0yWapOBQVsVrDl58W86//e1VpMNBtRV4MaXfdMySFA==",
      "dev": true,
      "license": "Apache-2.0",
      "dependencies": {
        "tslib": "^2.1.0"
      }
    },
    "node_modules/safe-buffer": {
      "version": "5.2.1",
      "resolved": "https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.2.1.tgz",
      "integrity": "sha512-rp3So07KcdmmKbGvgaNxQSJr7bGVSVk5S9Eq1F+ppbRo70+YeaDxkw5Dd8NPN+GD6bjnYm2VuPuCXmpuYvmCXQ==",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT"
    },
    "node_modules/safer-buffer": {
      "version": "2.1.2",
      "resolved": "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz",
      "integrity": "sha512-YZo3K82SD7Riyi0E1EQPojLz7kpepnSQI9IyPbHHg1XXXevb5dJI7tpyN2ADxGcQbHG7vcyRHk0cbwqcQriUtg==",
      "license": "MIT"
    },
    "node_modules/scheduler": {
      "version": "0.26.0",
      "resolved": "https://registry.npmjs.org/scheduler/-/scheduler-0.26.0.tgz",
      "integrity": "sha512-NlHwttCI/l5gCPR3D1nNXtWABUmBwvZpEQiD4IXSbIDq8BzLIK/7Ir5gTFSGZDUu37K5cMNp0hFtzO38sC7gWA==",
      "license": "MIT"
    },
    "node_modules/semver": {
      "version": "7.7.4",
      "resolved": "https://registry.npmjs.org/semver/-/semver-7.7.4.tgz",
      "integrity": "sha512-vFKC2IEtQnVhpT78h1Yp8wzwrf8CM+MzKMHGJZfBtzhZNycRFnXsHk6E5TxIkkMsgNS7mdX3AGB7x2QM2di4lA==",
      "license": "ISC",
      "bin": {
        "semver": "bin/semver.js"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/send": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/send/-/send-1.2.1.tgz",
      "integrity": "sha512-1gnZf7DFcoIcajTjTwjwuDjzuz4PPcY2StKPlsGAQ1+YH20IRVrBaXSWmdjowTJ6u8Rc01PoYOGHXfP1mYcZNQ==",
      "license": "MIT",
      "dependencies": {
        "debug": "^4.4.3",
        "encodeurl": "^2.0.0",
        "escape-html": "^1.0.3",
        "etag": "^1.8.1",
        "fresh": "^2.0.0",
        "http-errors": "^2.0.1",
        "mime-types": "^3.0.2",
        "ms": "^2.1.3",
        "on-finished": "^2.4.1",
        "range-parser": "^1.2.1",
        "statuses": "^2.0.2"
      },
      "engines": {
        "node": ">= 18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/serve-static": {
      "version": "2.2.1",
      "resolved": "https://registry.npmjs.org/serve-static/-/serve-static-2.2.1.tgz",
      "integrity": "sha512-xRXBn0pPqQTVQiC8wyQrKs2MOlX24zQ0POGaj0kultvoOCstBQM5yvOhAVSUwOMjQtTvsPWoNCHfPGwaaQJhTw==",
      "license": "MIT",
      "dependencies": {
        "encodeurl": "^2.0.0",
        "escape-html": "^1.0.3",
        "parseurl": "^1.3.3",
        "send": "^1.2.0"
      },
      "engines": {
        "node": ">= 18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/setprototypeof": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.2.0.tgz",
      "integrity": "sha512-E5LDX7Wrp85Kil5bhZv46j8jOeboKq5JMmYM3gVGdGH8xFpPWXUMsNrlODCrkoxMEeNi/XZIwuRvY4XNwYMJpw==",
      "license": "ISC"
    },
    "node_modules/shell-quote": {
      "version": "1.8.3",
      "resolved": "https://registry.npmjs.org/shell-quote/-/shell-quote-1.8.3.tgz",
      "integrity": "sha512-ObmnIF4hXNg1BqhnHmgbDETF8dLPCggZWBjkQfhZpbszZnYur5DUljTcCHii5LC3J5E0yeO/1LIMyH+UvHQgyw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/side-channel": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/side-channel/-/side-channel-1.1.0.tgz",
      "integrity": "sha512-ZX99e6tRweoUXqR+VBrslhda51Nh5MTQwou5tnUDgbtyM0dBgmhEDtWGP/xbKn6hqfPRHujUNwz5fy/wbbhnpw==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0",
        "object-inspect": "^1.13.3",
        "side-channel-list": "^1.0.0",
        "side-channel-map": "^1.0.1",
        "side-channel-weakmap": "^1.0.2"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/side-channel-list": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/side-channel-list/-/side-channel-list-1.0.0.tgz",
      "integrity": "sha512-FCLHtRD/gnpCiCHEiJLOwdmFP+wzCmDEkc9y7NsYxeF4u7Btsn1ZuwgwJGxImImHicJArLP4R0yX4c2KCrMrTA==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0",
        "object-inspect": "^1.13.3"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/side-channel-map": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/side-channel-map/-/side-channel-map-1.0.1.tgz",
      "integrity": "sha512-VCjCNfgMsby3tTdo02nbjtM/ewra6jPHmpThenkTYh8pG9ucZ/1P8So4u4FGBek/BjpOVsDCMoLA/iuBKIFXRA==",
      "license": "MIT",
      "dependencies": {
        "call-bound": "^1.0.2",
        "es-errors": "^1.3.0",
        "get-intrinsic": "^1.2.5",
        "object-inspect": "^1.13.3"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/side-channel-weakmap": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/side-channel-weakmap/-/side-channel-weakmap-1.0.2.tgz",
      "integrity": "sha512-WPS/HvHQTYnHisLo9McqBHOJk2FkHO/tlpvldyrnem4aeQp4hai3gythswg6p01oSoTl58rcpiFAjF2br2Ak2A==",
      "license": "MIT",
      "dependencies": {
        "call-bound": "^1.0.2",
        "es-errors": "^1.3.0",
        "get-intrinsic": "^1.2.5",
        "object-inspect": "^1.13.3",
        "side-channel-map": "^1.0.1"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/simple-concat": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/simple-concat/-/simple-concat-1.0.1.tgz",
      "integrity": "sha512-cSFtAPtRhljv69IK0hTVZQ+OfE9nePi/rtJmw5UjHeVyVroEqJXP1sFztKUy1qU+xvz3u/sfYJLa947b7nAN2Q==",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT"
    },
    "node_modules/simple-get": {
      "version": "4.0.1",
      "resolved": "https://registry.npmjs.org/simple-get/-/simple-get-4.0.1.tgz",
      "integrity": "sha512-brv7p5WgH0jmQJr1ZDDfKDOSeWWg+OVypG99A/5vYGPqJ6pxiaHLy8nxtFjBA7oMa01ebA9gfh1uMCFqOuXxvA==",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "decompress-response": "^6.0.0",
        "once": "^1.3.1",
        "simple-concat": "^1.0.0"
      }
    },
    "node_modules/source-map-js": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/source-map-js/-/source-map-js-1.2.1.tgz",
      "integrity": "sha512-UXWMKhLOwVKb728IUtQPXxfYU+usdybtUrK/8uGE8CQMvrhOpwvzDBwj0QhSL7MQc7vIsISBG8VQ8+IDQxpfQA==",
      "dev": true,
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/statuses": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/statuses/-/statuses-2.0.2.tgz",
      "integrity": "sha512-DvEy55V3DB7uknRo+4iOGT5fP1slR8wQohVdknigZPMpMstaKJQWhwiYBACJE3Ul2pTnATihhBYnRhZQHGBiRw==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/streamsearch": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/streamsearch/-/streamsearch-1.1.0.tgz",
      "integrity": "sha512-Mcc5wHehp9aXz1ax6bZUyY5afg9u2rv5cqQI3mRrYkGC8rW2hM02jWuwjtL++LS5qinSyhj2QfLyNsuc+VsExg==",
      "engines": {
        "node": ">=10.0.0"
      }
    },
    "node_modules/string_decoder": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/string_decoder/-/string_decoder-1.3.0.tgz",
      "integrity": "sha512-hkRX8U1WjJFd8LsDJ2yQ/wWWxaopEsABU1XfkM8A+j0+85JAGppt16cr1Whg6KIbb4okU6Mql6BOj+uup/wKeA==",
      "license": "MIT",
      "dependencies": {
        "safe-buffer": "~5.2.0"
      }
    },
    "node_modules/string-width": {
      "version": "4.2.3",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
      "integrity": "sha512-wKyQRQpjJ0sIp62ErSZdGsjMJWsap5oRNihHhu6G7JVO/9jIB6UyevL+tXuOqrng8j/cxKTWyWUwvSTriiZz/g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "emoji-regex": "^8.0.0",
        "is-fullwidth-code-point": "^3.0.0",
        "strip-ansi": "^6.0.1"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/strip-ansi": {
      "version": "6.0.1",
      "resolved": "https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz",
      "integrity": "sha512-Y38VPSHcqkFrCpFnQ9vuSXmquuv5oXOKpGeT6aGrr3o3Gc9AlVa6JBfUSOCnbxGGZF+/0ooI7KrPuUSztUdU5A==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "ansi-regex": "^5.0.1"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/strip-json-comments": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/strip-json-comments/-/strip-json-comments-2.0.1.tgz",
      "integrity": "sha512-4gB8na07fecVVkOI6Rs4e7T6NOTki5EmL7TUduTs6bu3EdnSycntVJ4re8kgZA+wx9IueI2Y11bfbgwtzuE0KQ==",
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/supports-color": {
      "version": "8.1.1",
      "resolved": "https://registry.npmjs.org/supports-color/-/supports-color-8.1.1.tgz",
      "integrity": "sha512-MpUEN2OodtUzxvKQl72cUF7RQ5EiHsGvSsVG0ia9c5RbWGL2CI4C7EpPS8UTBIplnlzZiNuV56w+FuNxy3ty2Q==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "has-flag": "^4.0.0"
      },
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/chalk/supports-color?sponsor=1"
      }
    },
    "node_modules/tar-fs": {
      "version": "2.1.4",
      "resolved": "https://registry.npmjs.org/tar-fs/-/tar-fs-2.1.4.tgz",
      "integrity": "sha512-mDAjwmZdh7LTT6pNleZ05Yt65HC3E+NiQzl672vQG38jIrehtJk/J3mNwIg+vShQPcLF/LV7CMnDW6vjj6sfYQ==",
      "license": "MIT",
      "dependencies": {
        "chownr": "^1.1.1",
        "mkdirp-classic": "^0.5.2",
        "pump": "^3.0.0",
        "tar-stream": "^2.1.4"
      }
    },
    "node_modules/tar-stream": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/tar-stream/-/tar-stream-2.2.0.tgz",
      "integrity": "sha512-ujeqbceABgwMZxEJnk2HDY2DlnUZ+9oEcb1KzTVfYHio0UE6dG71n60d8D2I4qNvleWrrXpmjpt7vZeF1LnMZQ==",
      "license": "MIT",
      "dependencies": {
        "bl": "^4.0.3",
        "end-of-stream": "^1.4.1",
        "fs-constants": "^1.0.0",
        "inherits": "^2.0.3",
        "readable-stream": "^3.1.1"
      },
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/tiny-invariant": {
      "version": "1.3.3",
      "resolved": "https://registry.npmjs.org/tiny-invariant/-/tiny-invariant-1.3.3.tgz",
      "integrity": "sha512-+FbBPE1o9QAYvviau/qC5SE3caw21q3xkvWKBtja5vgqOWIHHJ3ioaq1VPfn/Szqctz2bU/oYeKd9/z5BL+PVg==",
      "license": "MIT"
    },
    "node_modules/tinyglobby": {
      "version": "0.2.14",
      "resolved": "https://registry.npmjs.org/tinyglobby/-/tinyglobby-0.2.14.tgz",
      "integrity": "sha512-tX5e7OM1HnYr2+a2C/4V0htOcSQcoSTH9KgJnVvNm5zm/cyEWKJ7j7YutsH9CxMdtOkkLFy2AHrMci9IM8IPZQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "fdir": "^6.4.4",
        "picomatch": "^4.0.2"
      },
      "engines": {
        "node": ">=12.0.0"
      },
      "funding": {
        "url": "https://github.com/sponsors/SuperchupuDev"
      }
    },
    "node_modules/toidentifier": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/toidentifier/-/toidentifier-1.0.1.tgz",
      "integrity": "sha512-o5sSPKEkg/DIQNmH43V0/uerLrpzVedkUh8tGNvaeXpfpuwjKenlSox/2O/BTlZUtEe+JG7s5YhEz608PlAHRA==",
      "license": "MIT",
      "engines": {
        "node": ">=0.6"
      }
    },
    "node_modules/tr46": {
      "version": "0.0.3",
      "resolved": "https://registry.npmjs.org/tr46/-/tr46-0.0.3.tgz",
      "integrity": "sha512-N3WMsuqV66lT30CrXNbEjx4GEwlow3v6rr4mCcv6prnfwhS01rkgyFdjPNBYd9br7LpXV1+Emh01fHnq2Gdgrw==",
      "license": "MIT"
    },
    "node_modules/tree-kill": {
      "version": "1.2.2",
      "resolved": "https://registry.npmjs.org/tree-kill/-/tree-kill-1.2.2.tgz",
      "integrity": "sha512-L0Orpi8qGpRG//Nd+H90vFB+3iHnue1zSSGmNOOCh1GLJ7rUKVwV2HvijphGQS2UmhUZewS9VgvxYIdgr+fG1A==",
      "dev": true,
      "license": "MIT",
      "bin": {
        "tree-kill": "cli.js"
      }
    },
    "node_modules/tslib": {
      "version": "2.8.1",
      "resolved": "https://registry.npmjs.org/tslib/-/tslib-2.8.1.tgz",
      "integrity": "sha512-oJFu94HQb+KVduSUQL7wnpmqnfmLsOA/nAh6b6EH0wCEoK0/mPeXU6c3wKDV83MkOuHPRHtSXKKU99IBazS/2w==",
      "dev": true,
      "license": "0BSD"
    },
    "node_modules/tsx": {
      "version": "4.21.0",
      "resolved": "https://registry.npmjs.org/tsx/-/tsx-4.21.0.tgz",
      "integrity": "sha512-5C1sg4USs1lfG0GFb2RLXsdpXqBSEhAaA/0kPL01wxzpMqLILNxIxIOKiILz+cdg/pLnOUxFYOR5yhHU666wbw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "esbuild": "~0.27.0",
        "get-tsconfig": "^4.7.5"
      },
      "bin": {
        "tsx": "dist/cli.mjs"
      },
      "engines": {
        "node": ">=18.0.0"
      },
      "optionalDependencies": {
        "fsevents": "~2.3.3"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/aix-ppc64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/aix-ppc64/-/aix-ppc64-0.27.4.tgz",
      "integrity": "sha512-cQPwL2mp2nSmHHJlCyoXgHGhbEPMrEEU5xhkcy3Hs/O7nGZqEpZ2sUtLaL9MORLtDfRvVl2/3PAuEkYZH0Ty8Q==",
      "cpu": [
        "ppc64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "aix"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/android-arm": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm/-/android-arm-0.27.4.tgz",
      "integrity": "sha512-X9bUgvxiC8CHAGKYufLIHGXPJWnr0OCdR0anD2e21vdvgCI8lIfqFbnoeOz7lBjdrAGUhqLZLcQo6MLhTO2DKQ==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/android-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm64/-/android-arm64-0.27.4.tgz",
      "integrity": "sha512-gdLscB7v75wRfu7QSm/zg6Rx29VLdy9eTr2t44sfTW7CxwAtQghZ4ZnqHk3/ogz7xao0QAgrkradbBzcqFPasw==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/android-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/android-x64/-/android-x64-0.27.4.tgz",
      "integrity": "sha512-PzPFnBNVF292sfpfhiyiXCGSn9HZg5BcAz+ivBuSsl6Rk4ga1oEXAamhOXRFyMcjwr2DVtm40G65N3GLeH1Lvw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/darwin-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.27.4.tgz",
      "integrity": "sha512-b7xaGIwdJlht8ZFCvMkpDN6uiSmnxxK56N2GDTMYPr2/gzvfdQN8rTfBsvVKmIVY/X7EM+/hJKEIbbHs9oA4tQ==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/darwin-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.27.4.tgz",
      "integrity": "sha512-sR+OiKLwd15nmCdqpXMnuJ9W2kpy0KigzqScqHI3Hqwr7IXxBp3Yva+yJwoqh7rE8V77tdoheRYataNKL4QrPw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/freebsd-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-arm64/-/freebsd-arm64-0.27.4.tgz",
      "integrity": "sha512-jnfpKe+p79tCnm4GVav68A7tUFeKQwQyLgESwEAUzyxk/TJr4QdGog9sqWNcUbr/bZt/O/HXouspuQDd9JxFSw==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/freebsd-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-x64/-/freebsd-x64-0.27.4.tgz",
      "integrity": "sha512-2kb4ceA/CpfUrIcTUl1wrP/9ad9Atrp5J94Lq69w7UwOMolPIGrfLSvAKJp0RTvkPPyn6CIWrNy13kyLikZRZQ==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-arm": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm/-/linux-arm-0.27.4.tgz",
      "integrity": "sha512-aBYgcIxX/wd5n2ys0yESGeYMGF+pv6g0DhZr3G1ZG4jMfruU9Tl1i2Z+Wnj9/KjGz1lTLCcorqE2viePZqj4Eg==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm64/-/linux-arm64-0.27.4.tgz",
      "integrity": "sha512-7nQOttdzVGth1iz57kxg9uCz57dxQLHWxopL6mYuYthohPKEK0vU0C3O21CcBK6KDlkYVcnDXY099HcCDXd9dA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-ia32": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ia32/-/linux-ia32-0.27.4.tgz",
      "integrity": "sha512-oPtixtAIzgvzYcKBQM/qZ3R+9TEUd1aNJQu0HhGyqtx6oS7qTpvjheIWBbes4+qu1bNlo2V4cbkISr8q6gRBFA==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-loong64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-loong64/-/linux-loong64-0.27.4.tgz",
      "integrity": "sha512-8mL/vh8qeCoRcFH2nM8wm5uJP+ZcVYGGayMavi8GmRJjuI3g1v6Z7Ni0JJKAJW+m0EtUuARb6Lmp4hMjzCBWzA==",
      "cpu": [
        "loong64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-mips64el": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-mips64el/-/linux-mips64el-0.27.4.tgz",
      "integrity": "sha512-1RdrWFFiiLIW7LQq9Q2NES+HiD4NyT8Itj9AUeCl0IVCA459WnPhREKgwrpaIfTOe+/2rdntisegiPWn/r/aAw==",
      "cpu": [
        "mips64el"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-ppc64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ppc64/-/linux-ppc64-0.27.4.tgz",
      "integrity": "sha512-tLCwNG47l3sd9lpfyx9LAGEGItCUeRCWeAx6x2Jmbav65nAwoPXfewtAdtbtit/pJFLUWOhpv0FpS6GQAmPrHA==",
      "cpu": [
        "ppc64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-riscv64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-riscv64/-/linux-riscv64-0.27.4.tgz",
      "integrity": "sha512-BnASypppbUWyqjd1KIpU4AUBiIhVr6YlHx/cnPgqEkNoVOhHg+YiSVxM1RLfiy4t9cAulbRGTNCKOcqHrEQLIw==",
      "cpu": [
        "riscv64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-s390x": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-s390x/-/linux-s390x-0.27.4.tgz",
      "integrity": "sha512-+eUqgb/Z7vxVLezG8bVB9SfBie89gMueS+I0xYh2tJdw3vqA/0ImZJ2ROeWwVJN59ihBeZ7Tu92dF/5dy5FttA==",
      "cpu": [
        "s390x"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/linux-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.27.4.tgz",
      "integrity": "sha512-S5qOXrKV8BQEzJPVxAwnryi2+Iq5pB40gTEIT69BQONqR7JH1EPIcQ/Uiv9mCnn05jff9umq/5nqzxlqTOg9NA==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/netbsd-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-arm64/-/netbsd-arm64-0.27.4.tgz",
      "integrity": "sha512-xHT8X4sb0GS8qTqiwzHqpY00C95DPAq7nAwX35Ie/s+LO9830hrMd3oX0ZMKLvy7vsonee73x0lmcdOVXFzd6Q==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/netbsd-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-x64/-/netbsd-x64-0.27.4.tgz",
      "integrity": "sha512-RugOvOdXfdyi5Tyv40kgQnI0byv66BFgAqjdgtAKqHoZTbTF2QqfQrFwa7cHEORJf6X2ht+l9ABLMP0dnKYsgg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/openbsd-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-arm64/-/openbsd-arm64-0.27.4.tgz",
      "integrity": "sha512-2MyL3IAaTX+1/qP0O1SwskwcwCoOI4kV2IBX1xYnDDqthmq5ArrW94qSIKCAuRraMgPOmG0RDTA74mzYNQA9ow==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/openbsd-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-x64/-/openbsd-x64-0.27.4.tgz",
      "integrity": "sha512-u8fg/jQ5aQDfsnIV6+KwLOf1CmJnfu1ShpwqdwC0uA7ZPwFws55Ngc12vBdeUdnuWoQYx/SOQLGDcdlfXhYmXQ==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/openharmony-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/openharmony-arm64/-/openharmony-arm64-0.27.4.tgz",
      "integrity": "sha512-JkTZrl6VbyO8lDQO3yv26nNr2RM2yZzNrNHEsj9bm6dOwwu9OYN28CjzZkH57bh4w0I2F7IodpQvUAEd1mbWXg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openharmony"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/sunos-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/sunos-x64/-/sunos-x64-0.27.4.tgz",
      "integrity": "sha512-/gOzgaewZJfeJTlsWhvUEmUG4tWEY2Spp5M20INYRg2ZKl9QPO3QEEgPeRtLjEWSW8FilRNacPOg8R1uaYkA6g==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "sunos"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/win32-arm64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-arm64/-/win32-arm64-0.27.4.tgz",
      "integrity": "sha512-Z9SExBg2y32smoDQdf1HRwHRt6vAHLXcxD2uGgO/v2jK7Y718Ix4ndsbNMU/+1Qiem9OiOdaqitioZwxivhXYg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/win32-ia32": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-ia32/-/win32-ia32-0.27.4.tgz",
      "integrity": "sha512-DAyGLS0Jz5G5iixEbMHi5KdiApqHBWMGzTtMiJ72ZOLhbu/bzxgAe8Ue8CTS3n3HbIUHQz/L51yMdGMeoxXNJw==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/@esbuild/win32-x64": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-0.27.4.tgz",
      "integrity": "sha512-+knoa0BDoeXgkNvvV1vvbZX4+hizelrkwmGJBdT17t8FNPwG2lKemmuMZlmaNQ3ws3DKKCxpb4zRZEIp3UxFCg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/tsx/node_modules/esbuild": {
      "version": "0.27.4",
      "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.27.4.tgz",
      "integrity": "sha512-Rq4vbHnYkK5fws5NF7MYTU68FPRE1ajX7heQ/8QXXWqNgqqJ/GkmmyxIzUnf2Sr/bakf8l54716CcMGHYhMrrQ==",
      "dev": true,
      "hasInstallScript": true,
      "license": "MIT",
      "bin": {
        "esbuild": "bin/esbuild"
      },
      "engines": {
        "node": ">=18"
      },
      "optionalDependencies": {
        "@esbuild/aix-ppc64": "0.27.4",
        "@esbuild/android-arm": "0.27.4",
        "@esbuild/android-arm64": "0.27.4",
        "@esbuild/android-x64": "0.27.4",
        "@esbuild/darwin-arm64": "0.27.4",
        "@esbuild/darwin-x64": "0.27.4",
        "@esbuild/freebsd-arm64": "0.27.4",
        "@esbuild/freebsd-x64": "0.27.4",
        "@esbuild/linux-arm": "0.27.4",
        "@esbuild/linux-arm64": "0.27.4",
        "@esbuild/linux-ia32": "0.27.4",
        "@esbuild/linux-loong64": "0.27.4",
        "@esbuild/linux-mips64el": "0.27.4",
        "@esbuild/linux-ppc64": "0.27.4",
        "@esbuild/linux-riscv64": "0.27.4",
        "@esbuild/linux-s390x": "0.27.4",
        "@esbuild/linux-x64": "0.27.4",
        "@esbuild/netbsd-arm64": "0.27.4",
        "@esbuild/netbsd-x64": "0.27.4",
        "@esbuild/openbsd-arm64": "0.27.4",
        "@esbuild/openbsd-x64": "0.27.4",
        "@esbuild/openharmony-arm64": "0.27.4",
        "@esbuild/sunos-x64": "0.27.4",
        "@esbuild/win32-arm64": "0.27.4",
        "@esbuild/win32-ia32": "0.27.4",
        "@esbuild/win32-x64": "0.27.4"
      }
    },
    "node_modules/tunnel-agent": {
      "version": "0.6.0",
      "resolved": "https://registry.npmjs.org/tunnel-agent/-/tunnel-agent-0.6.0.tgz",
      "integrity": "sha512-McnNiV1l8RYeY8tBgEpuodCC1mLUdbSN+CYBL7kJsJNInOP8UjDDEwdk6Mw60vdLLrr5NHKZhMAOSrR2NZuQ+w==",
      "license": "Apache-2.0",
      "dependencies": {
        "safe-buffer": "^5.0.1"
      },
      "engines": {
        "node": "*"
      }
    },
    "node_modules/type-is": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/type-is/-/type-is-2.0.1.tgz",
      "integrity": "sha512-OZs6gsjF4vMp32qrCbiVSkrFmXtG/AZhY3t0iAMrMBiAZyV9oALtXO8hsrHbMXF9x6L3grlFuwW2oAz7cav+Gw==",
      "license": "MIT",
      "dependencies": {
        "content-type": "^1.0.5",
        "media-typer": "^1.1.0",
        "mime-types": "^3.0.0"
      },
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/typedarray": {
      "version": "0.0.6",
      "resolved": "https://registry.npmjs.org/typedarray/-/typedarray-0.0.6.tgz",
      "integrity": "sha512-/aCDEGatGvZ2BIk+HmLf4ifCJFwvKFNb9/JeZPMulfgFracn9QFcAf5GO8B/mweUjSoblS5In0cWhqpfs/5PQA==",
      "license": "MIT"
    },
    "node_modules/typescript": {
      "version": "5.7.3",
      "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.7.3.tgz",
      "integrity": "sha512-84MVSjMEHP+FQRPy3pX9sTVV/INIex71s9TL2Gm5FG/WG1SqXeKyZ0k7/blY/4FdOzI12CBy1vGc4og/eus0fw==",
      "dev": true,
      "license": "Apache-2.0",
      "bin": {
        "tsc": "bin/tsc",
        "tsserver": "bin/tsserver"
      },
      "engines": {
        "node": ">=14.17"
      }
    },
    "node_modules/undici-types": {
      "version": "6.21.0",
      "resolved": "https://registry.npmjs.org/undici-types/-/undici-types-6.21.0.tgz",
      "integrity": "sha512-iwDZqg0QAGrg9Rav5H4n0M64c3mkR59cJ6wQp+7C4nI0gsmExaedaYLNO44eT4AtBBwjbTiGPMlt2Md0T9H9JQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/unpipe": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz",
      "integrity": "sha512-pjy2bYhSsufwWlKwPc+l3cN7+wuJlK6uz0YdJEOlQDbl6jo/YlPi4mb8agUkVC8BF7V8NuzeyPNqRksA3hztKQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/use-sync-external-store": {
      "version": "1.6.0",
      "resolved": "https://registry.npmjs.org/use-sync-external-store/-/use-sync-external-store-1.6.0.tgz",
      "integrity": "sha512-Pp6GSwGP/NrPIrxVFAIkOQeyw8lFenOHijQWkUTrDvrF4ALqylP2C/KCkeS9dpUM3KvYRQhna5vt7IL95+ZQ9w==",
      "license": "MIT",
      "peerDependencies": {
        "react": "^16.8.0 || ^17.0.0 || ^18.0.0 || ^19.0.0"
      }
    },
    "node_modules/util-deprecate": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/util-deprecate/-/util-deprecate-1.0.2.tgz",
      "integrity": "sha512-EPD5q1uXyFxJpCrLnCc1nHnq3gOa6DZBocAIiI2TaSCA7VCJ1UJDMagCzIkXNsUYfD1daK//LTEQ8xiIbrHtcw==",
      "license": "MIT"
    },
    "node_modules/uuid": {
      "version": "9.0.1",
      "resolved": "https://registry.npmjs.org/uuid/-/uuid-9.0.1.tgz",
      "integrity": "sha512-b+1eJOlsR9K8HJpow9Ok3fiWOWSIcIzXodvv0rQjVoOVNpWMpxf1wZNpt4y9h10odCNrqnYp1OBzRktckBe3sA==",
      "funding": [
        "https://github.com/sponsors/broofa",
        "https://github.com/sponsors/ctavan"
      ],
      "license": "MIT",
      "bin": {
        "uuid": "dist/bin/uuid"
      }
    },
    "node_modules/vary": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/vary/-/vary-1.1.2.tgz",
      "integrity": "sha512-BNGbWLfd0eUPabhkXUVm0j8uuvREyTh5ovRa/dyow/BqAbZJyC+5fU+IzQOzmAKzYqYRAISoRhdQr3eIZ/PXqg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/victory-vendor": {
      "version": "37.3.6",
      "resolved": "https://registry.npmjs.org/victory-vendor/-/victory-vendor-37.3.6.tgz",
      "integrity": "sha512-SbPDPdDBYp+5MJHhBCAyI7wKM3d5ivekigc2Dk2s7pgbZ9wIgIBYGVw4zGHBml/qTFbexrofXW6Gu4noGxrOwQ==",
      "license": "MIT AND ISC",
      "dependencies": {
        "@types/d3-array": "^3.0.3",
        "@types/d3-ease": "^3.0.0",
        "@types/d3-interpolate": "^3.0.1",
        "@types/d3-scale": "^4.0.2",
        "@types/d3-shape": "^3.1.0",
        "@types/d3-time": "^3.0.0",
        "@types/d3-timer": "^3.0.0",
        "d3-array": "^3.1.6",
        "d3-ease": "^3.0.1",
        "d3-interpolate": "^3.0.1",
        "d3-scale": "^4.0.2",
        "d3-shape": "^3.1.0",
        "d3-time": "^3.0.0",
        "d3-timer": "^3.0.1"
      }
    },
    "node_modules/vite": {
      "version": "6.3.5",
      "resolved": "https://registry.npmjs.org/vite/-/vite-6.3.5.tgz",
      "integrity": "sha512-cZn6NDFE7wdTpINgs++ZJ4N49W2vRp8LCKrn3Ob1kYNtOo21vfDoaV5GzBfLU4MovSAB8uNRm4jgzVQZ+mBzPQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "esbuild": "^0.25.0",
        "fdir": "^6.4.4",
        "picomatch": "^4.0.2",
        "postcss": "^8.5.3",
        "rollup": "^4.34.9",
        "tinyglobby": "^0.2.13"
      },
      "bin": {
        "vite": "bin/vite.js"
      },
      "engines": {
        "node": "^18.0.0 || ^20.0.0 || >=22.0.0"
      },
      "funding": {
        "url": "https://github.com/vitejs/vite?sponsor=1"
      },
      "optionalDependencies": {
        "fsevents": "~2.3.3"
      },
      "peerDependencies": {
        "@types/node": "^18.0.0 || ^20.0.0 || >=22.0.0",
        "jiti": ">=1.21.0",
        "less": "*",
        "lightningcss": "^1.21.0",
        "sass": "*",
        "sass-embedded": "*",
        "stylus": "*",
        "sugarss": "*",
        "terser": "^5.16.0",
        "tsx": "^4.8.1",
        "yaml": "^2.4.2"
      },
      "peerDependenciesMeta": {
        "@types/node": {
          "optional": true
        },
        "jiti": {
          "optional": true
        },
        "less": {
          "optional": true
        },
        "lightningcss": {
          "optional": true
        },
        "sass": {
          "optional": true
        },
        "sass-embedded": {
          "optional": true
        },
        "stylus": {
          "optional": true
        },
        "sugarss": {
          "optional": true
        },
        "terser": {
          "optional": true
        },
        "tsx": {
          "optional": true
        },
        "yaml": {
          "optional": true
        }
      }
    },
    "node_modules/webidl-conversions": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/webidl-conversions/-/webidl-conversions-3.0.1.tgz",
      "integrity": "sha512-2JAn3z8AR6rjK8Sm8orRC0h/bcl/DqL7tRPdGZ4I1CjdF+EaMLmYxBHyXuKL849eucPFhvBoxMsflfOb8kxaeQ==",
      "license": "BSD-2-Clause"
    },
    "node_modules/whatwg-url": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/whatwg-url/-/whatwg-url-5.0.0.tgz",
      "integrity": "sha512-saE57nupxk6v3HY35+jzBwYa0rKSy0XR8JSxZPwgLr7ys0IBzhGviA1/TUGJLmSVqs8pb9AnvICXEuOHLprYTw==",
      "license": "MIT",
      "dependencies": {
        "tr46": "~0.0.3",
        "webidl-conversions": "^3.0.0"
      }
    },
    "node_modules/wrap-ansi": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/wrap-ansi/-/wrap-ansi-7.0.0.tgz",
      "integrity": "sha512-YVGIj2kamLSTxw6NsZjoBxfSwsn0ycdesmc4p+Q21c5zPuZ1pl+NfxVdxPtdHvmNVOQ6XSYG4AUtyt/Fi7D16Q==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "ansi-styles": "^4.0.0",
        "string-width": "^4.1.0",
        "strip-ansi": "^6.0.0"
      },
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/chalk/wrap-ansi?sponsor=1"
      }
    },
    "node_modules/wrappy": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/wrappy/-/wrappy-1.0.2.tgz",
      "integrity": "sha512-l4Sp/DRseor9wL6EvV2+TuQn63dMkPjZ/sp9XkghTEbV9KlPS1xUsZ3u7/IQO4wxtcFB4bgpQPRcR3QCvezPcQ==",
      "license": "ISC"
    },
    "node_modules/ws": {
      "version": "8.19.0",
      "resolved": "https://registry.npmjs.org/ws/-/ws-8.19.0.tgz",
      "integrity": "sha512-blAT2mjOEIi0ZzruJfIhb3nps74PRWTCz1IjglWEEpQl5XS/UNama6u2/rjFkDDouqr4L67ry+1aGIALViWjDg==",
      "license": "MIT",
      "engines": {
        "node": ">=10.0.0"
      },
      "peerDependencies": {
        "bufferutil": "^4.0.1",
        "utf-8-validate": ">=5.0.2"
      },
      "peerDependenciesMeta": {
        "bufferutil": {
          "optional": true
        },
        "utf-8-validate": {
          "optional": true
        }
      }
    },
    "node_modules/y18n": {
      "version": "5.0.8",
      "resolved": "https://registry.npmjs.org/y18n/-/y18n-5.0.8.tgz",
      "integrity": "sha512-0pfFzegeDWJHJIAmTLRP2DwHjdF5s7jo9tuztdQxAhINCdvS+3nGINqPd00AphqJR/0LhANUS6/+7SCb98YOfA==",
      "dev": true,
      "license": "ISC",
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/yargs": {
      "version": "17.7.2",
      "resolved": "https://registry.npmjs.org/yargs/-/yargs-17.7.2.tgz",
      "integrity": "sha512-7dSzzRQ++CKnNI/krKnYRV7JKKPUXMEh61soaHKg9mrWEhzFWhFnxPxGl+69cD1Ou63C13NUPCnmIcrvqCuM6w==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "cliui": "^8.0.1",
        "escalade": "^3.1.1",
        "get-caller-file": "^2.0.5",
        "require-directory": "^2.1.1",
        "string-width": "^4.2.3",
        "y18n": "^5.0.5",
        "yargs-parser": "^21.1.1"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/yargs-parser": {
      "version": "21.1.1",
      "resolved": "https://registry.npmjs.org/yargs-parser/-/yargs-parser-21.1.1.tgz",
      "integrity": "sha512-tVpsJW7DdjecAiFpbIB1e3qxIQsE6NoPc5/eTdrbbIC4h0LVsWhnoa3g+m2HclBIujHzsxZ4VJVA+GUuc2/LBw==",
      "dev": true,
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/zod": {
      "version": "4.3.6",
      "resolved": "https://registry.npmjs.org/zod/-/zod-4.3.6.tgz",
      "integrity": "sha512-rftlrkhHZOcjDwkGlnUtZZkvaPHCsDATp4pGpuOOMDaTdDDXF91wuVDJoWoPsKX/3YPQ5fHuF3STjcYyKr+Qhg==",
      "license": "MIT",
      "funding": {
        "url": "https://github.com/sponsors/colinhacks"
      }
    }
  }
}

```

## File: `package.json`  
- Path: `package.json`  
- Size: 972 Bytes  
- Modified: 2026-03-13 14:05:28 UTC

```json
{
  "name": "netguard-ai",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "concurrently \"npm:dev:server\" \"npm:dev:client\"",
    "dev:client": "vite",
    "dev:server": "node --watch server/index.js",
    "build": "vite build",
    "preview": "vite preview",
    "server": "node server/index.js",
    "reset:state": "node server/resetState.js"
  },
  "dependencies": {
    "@google/genai": "^1.9.0",
    "better-sqlite3": "^12.6.2",
    "cap": "^0.2.1",
    "dexie": "^4.3.0",
    "express": "^5.2.1",
    "lru-cache": "^11.2.6",
    "multer": "^2.1.1",
    "pcap-parser": "^0.2.1",
    "pcap-writer": "^1.0.1",
    "react": "^19.1.0",
    "react-dom": "^19.1.0",
    "recharts": "^3.8.0",
    "ws": "^8.19.0",
    "zod": "^4.3.6"
  },
  "devDependencies": {
    "@types/express": "^5.0.6",
    "@types/node": "^22.14.0",
    "concurrently": "^9.2.1",
    "tsx": "^4.21.0",
    "typescript": "~5.7.2",
    "vite": "^6.2.0"
  }
}

```

## File: `public/locales/translations.ts`  
- Path: `public/locales/translations.ts`  
- Size: 10907 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```typescript

const en = {
    "headerTitle": "NetGuard AI",
    "dashboardTitle": "Real-time Traffic & Threats",

    "monitoringStatusCardTitle": "Monitoring Status",
    "llmStatusCardTitle": "LLM Status",
    "packetsProcessedCardTitle": "Packets Processed",
    "threatsDetectedCardTitle": "Threats Detected",

    "activeStatus": "Active",
    "stoppedStatus": "Stopped",
    "loadedStatus": "Loaded",
    "listeningOnPorts": "Listening on all ports",
    "sinceLastStart": "Since last start",
    "last24Hours": "Last 24 hours",
    
    "startMonitoringButton": "Start Monitoring",
    "stopMonitoringButton": "Stop Monitoring",

    "dashboardTab": "Dashboard",
    "settingsTab": "Settings",
    "logsTab": "Logs",

    "liveTrafficFeed": "Live Traffic Feed",
    "threatAlerts": "Threat Alerts",
    "confidence": "Confidence",
    "startMonitoringToSeeTraffic": "Start monitoring to see live traffic...",
    "waitingForTraffic": "Monitoring active, waiting for traffic...",
    "noThreatsDetected": "No threats detected yet.",

    "colTimestamp": "Timestamp",
    "colSourceIp": "Source IP",
    "colDestPort": "Dest Port",
    "colProtocol": "Protocol",
    "colAttackType": "Attack Type",
    "colConfidence": "Confidence",
    "colAction": "Action",
    "colLlmExplanation": "LLM Explanation",

    "settingsTitle": "Settings",
    "settingsLlmConfig": "LLM Configuration",
    "llmProvider": "LLM Provider",
    "geminiModel": "Gemini Model",
    "lmStudioModel": "LM Studio Model",
    "lmStudioBaseUrl": "LM Studio Base URL",
    "lmStudioUrlHint": "e.g., http://localhost:1234/v1. Make sure 'CORS' is enabled in the LM Studio server settings.",
    "geminiApiNote": "Gemini API Key is managed via environment variables.",
    "settingsCoreConfig": "Core Configuration",
    "secureRedirectPort": "Secure Redirect Port",
    "monitoringPorts": "Monitoring Ports (comma-separated)",
    "autoBlockThreats": "Auto-block detected threats",
    "settingsRuleEngine": "Rule Engine",
    "detectionThreshold": "Detection Threshold",
    "detectionThresholdHint": "Confidence level required to trigger an action.",
    "blockedIpAddresses": "Blocked IP Addresses",
    "enterIpAddress": "Enter IP address...",
    "add": "Add",
    "remove": "Remove",
    "blockedPorts": "Blocked Ports",
    "settingsExemptPorts": "Exempt Ports",
    "enterPortNumber": "Enter port number...",
    "logsTitle": "Event Logs",
    "colLevel": "Level",
    "colMessage": "Message",
    "colDetails": "Details",
    "noLogsYet": "No logs yet. Start monitoring to generate events.",
    "localeCode": "en-US",
    "logPacketCaptured": "Packet captured",
    "logLlmAnalysisComplete": "LLM Analysis complete",
    "logBlockedByBlocklist": "IP/Port is on blocklist. Action: {type}",
    "logSuspiciousActivityReason": "Suspicious activity detected: {attackType}",
    "logSuspiciousTrafficDetected": "Suspicious traffic detected. Action: {type}",
    "logIpAutoBlocked": "IP {ip} auto-added to blocklist",
    "logTrafficAllowed": "Traffic allowed by rule engine",
    "logTrafficAllowedExempt": "Traffic allowed: Port {port} is on the exempt list.",
    "logActionTaken": "Action taken: {type}",
    "logAnalysisFailed": "Failed to analyze packet",
    "logMonitoringStarted": "Network monitoring started.",
    "logMonitoringStopped": "Network monitoring stopped.",
    "unknownError": "Unknown error"
};

const de = {
    "headerTitle": "NetGuard KI",
    "dashboardTitle": "Echtzeit-Verkehr & Bedrohungen",

    "monitoringStatusCardTitle": "Überwachungsstatus",
    "llmStatusCardTitle": "LLM-Status",
    "packetsProcessedCardTitle": "Verarbeitete Pakete",
    "threatsDetectedCardTitle": "Erkannte Bedrohungen",

    "activeStatus": "Aktiv",
    "stoppedStatus": "Gestoppt",
    "loadedStatus": "Geladen",
    "listeningOnPorts": "Lauscht auf allen Ports",
    "sinceLastStart": "Seit letztem Start",
    "last24Hours": "Letzte 24 Stunden",
    
    "startMonitoringButton": "Überwachung starten",
    "stopMonitoringButton": "Überwachung stoppen",

    "dashboardTab": "Dashboard",
    "settingsTab": "Einstellungen",
    "logsTab": "Protokolle",

    "liveTrafficFeed": "Live-Verkehrs-Feed",
    "threatAlerts": "Bedrohungswarnungen",
    "confidence": "Konfidenz",
    "startMonitoringToSeeTraffic": "Überwachung starten, um Live-Verkehr zu sehen...",
    "waitingForTraffic": "Überwachung aktiv, warte auf Verkehr...",
    "noThreatsDetected": "Noch keine Bedrohungen erkannt.",

    "colTimestamp": "Zeitstempel",
    "colSourceIp": "Quell-IP",
    "colDestPort": "Ziel-Port",
    "colProtocol": "Protokoll",
    "colAttackType": "Angriffstyp",
    "colConfidence": "Konfidenz",
    "colAction": "Aktion",
    "colLlmExplanation": "LLM-Erklärung",

    "settingsTitle": "Einstellungen",
    "settingsLlmConfig": "LLM-Konfiguration",
    "llmProvider": "LLM-Anbieter",
    "geminiModel": "Gemini-Modell",
    "lmStudioModel": "LM Studio-Modell",
    "lmStudioBaseUrl": "LM Studio Basis-URL",
    "lmStudioUrlHint": "z.B. http://localhost:1234/v1. Stellen Sie sicher, dass 'CORS' in den LM Studio-Servereinstellungen aktiviert ist.",
    "geminiApiNote": "Der Gemini API-Schlüssel wird über Umgebungsvariablen verwaltet.",
    "settingsCoreConfig": "Kernkonfiguration",
    "secureRedirectPort": "Sicherer Umleitungsport",
    "monitoringPorts": "Überwachungsports (kommagetrennt)",
    "autoBlockThreats": "Erkannte Bedrohungen automatisch blockieren",
    "settingsRuleEngine": "Regel-Engine",
    "detectionThreshold": "Erkennungsschwelle",
    "detectionThresholdHint": "Konfidenzniveau, das erforderlich ist, um eine Aktion auszulösen.",
    "blockedIpAddresses": "Blockierte IP-Adressen",
    "enterIpAddress": "IP-Adresse eingeben...",
    "add": "Hinzufügen",
    "remove": "Entfernen",
    "blockedPorts": "Blockierte Ports",
    "settingsExemptPorts": "Ausgenommene Ports",
    "enterPortNumber": "Portnummer eingeben...",
    "logsTitle": "Ereignisprotokolle",
    "colLevel": "Stufe",
    "colMessage": "Nachricht",
    "colDetails": "Details",
    "noLogsYet": "Noch keine Protokolle. Starten Sie die Überwachung, um Ereignisse zu generieren.",
    "localeCode": "de-DE",
    "logPacketCaptured": "Paket erfasst",
    "logLlmAnalysisComplete": "LLM-Analyse abgeschlossen",
    "logBlockedByBlocklist": "IP/Port ist auf der Sperrliste. Aktion: {type}",
    "logSuspiciousActivityReason": "Verdächtige Aktivität erkannt: {attackType}",
    "logSuspiciousTrafficDetected": "Verdächtiger Verkehr erkannt. Aktion: {type}",
    "logIpAutoBlocked": "IP {ip} automatisch zur Sperrliste hinzugefügt",
    "logTrafficAllowed": "Verkehr von Regel-Engine zugelassen",
    "logTrafficAllowedExempt": "Verkehr zugelassen: Port {port} ist auf der Ausnahmeliste.",
    "logActionTaken": "Aktion ausgeführt: {type}",
    "logAnalysisFailed": "Paketanalyse fehlgeschlagen",
    "logMonitoringStarted": "Netzwerküberwachung gestartet.",
    "logMonitoringStopped": "Netzwerküberwachung gestoppt.",
    "unknownError": "Unbekannter Fehler"
};

const es = {
    "headerTitle": "NetGuard AI",
    "dashboardTitle": "Tráfico y Amenazas en Tiempo Real",

    "monitoringStatusCardTitle": "Estado de Monitoreo",
    "llmStatusCardTitle": "Estado de LLM",
    "packetsProcessedCardTitle": "Paquetes Procesados",
    "threatsDetectedCardTitle": "Amenazas Detectadas",

    "activeStatus": "Activo",
    "stoppedStatus": "Detenido",
    "loadedStatus": "Cargado",
    "listeningOnPorts": "Escuchando en todos los puertos",
    "sinceLastStart": "Desde el último inicio",
    "last24Hours": "Últimas 24 horas",

    "startMonitoringButton": "Iniciar Monitoreo",
    "stopMonitoringButton": "Detener Monitoreo",
    
    "dashboardTab": "Tablero",
    "settingsTab": "Ajustes",
    "logsTab": "Registros",
    "liveTrafficFeed": "Fuente de Tráfico en Vivo",
    "threatAlerts": "Alertas de Amenazas",
    "confidence": "Confianza",
    "startMonitoringToSeeTraffic": "Inicie el monitoreo para ver el tráfico en vivo...",
    "waitingForTraffic": "Monitoreo activo, esperando tráfico...",
    "noThreatsDetected": "Aún no se han detectado amenazas.",
    "colTimestamp": "Marca de tiempo",
    "colSourceIp": "IP Origen",
    "colDestPort": "Puerto Dest",
    "colProtocol": "Protocolo",
    "colAttackType": "Tipo de Ataque",
    "colConfidence": "Confianza",
    "colAction": "Acción",
    "colLlmExplanation": "Explicación LLM",
    "settingsTitle": "Ajustes",
    "settingsLlmConfig": "Configuración de LLM",
    "llmProvider": "Proveedor de LLM",
    "geminiModel": "Modelo Gemini",
    "lmStudioModel": "Modelo de LM Studio",
    "lmStudioBaseUrl": "URL Base de LM Studio",
    "lmStudioUrlHint": "p. ej., http://localhost:1234/v1. Asegúrese de que 'CORS' esté habilitado en la configuración del servidor de LM Studio.",
    "geminiApiNote": "La clave de API de Gemini se gestiona mediante variables de entorno.",
    "settingsCoreConfig": "Configuración Central",
    "secureRedirectPort": "Puerto de Redirección Seguro",
    "monitoringPorts": "Puertos de Monitoreo (separados por comas)",
    "autoBlockThreats": "Bloquear amenazas detectadas automáticamente",
    "settingsRuleEngine": "Motor de Reglas",
    "detectionThreshold": "Umbral de Detección",
    "detectionThresholdHint": "Nivel de confianza requerido para activar una acción.",
    "blockedIpAddresses": "Direcciones IP Bloqueadas",
    "enterIpAddress": "Ingrese la dirección IP...",
    "add": "Añadir",
    "remove": "Eliminar",
    "blockedPorts": "Puertos Bloqueados",
    "settingsExemptPorts": "Puertos Exentos",
    "enterPortNumber": "Ingrese el número de puerto...",
    "logsTitle": "Registros de Eventos",
    "colLevel": "Nivel",
    "colMessage": "Mensaje",
    "colDetails": "Detalles",
    "noLogsYet": "Aún no hay registros. Inicie el monitoreo para generar eventos.",
    "localeCode": "es-ES",
    "logPacketCaptured": "Paquete capturado",
    "logLlmAnalysisComplete": "Análisis LLM completado",
    "logBlockedByBlocklist": "IP/Puerto está en la lista de bloqueo. Acción: {type}",
    "logSuspiciousActivityReason": "Actividad sospechosa detectada: {attackType}",
    "logSuspiciousTrafficDetected": "Tráfico sospechoso detectado. Acción: {type}",
    "logIpAutoBlocked": "IP {ip} auto-agregada a la lista de bloqueo",
    "logTrafficAllowed": "Tráfico permitido por el motor de reglas",
    "logTrafficAllowedExempt": "Tráfico permitido: El puerto {port} está en la lista de exentos.",
    "logActionTaken": "Acción tomada: {type}",
    "logAnalysisFailed": "Falló el análisis del paquete",
    "logMonitoringStarted": "Monitoreo de red iniciado.",
    "logMonitoringStopped": "Monitoreo de red detenido.",
    "unknownError": "Error desconocido"
};

export const translations = {
    en,
    de,
    es,
    fr: es,
    it: es,
    ja: en,
    nl: de,
    ru: en,
    zh: en,
    ar: en
};
```

## File: `README.md`  
- Path: `README.md`  
- Size: 4150 Bytes  
- Modified: 2026-03-13 14:08:38 UTC

```markdown
# NetGuard AI

NetGuard AI now runs as a backend-driven IDS/IPS stack with:

- real packet capture via `cap`/libpcap
- backend-side heuristics, LLM batching, caching and persistence
- SQLite storage for logs, traffic history and PCAP artifacts
- WebSocket updates for metrics, alerts, replay status and optional raw packets
- real OS firewall integration for block actions
- PCAP export plus historical replay mode
- a visual custom rule builder for pre-LLM decisions
- outbound webhook alerting from the backend service
- fleet mode with `standalone`, `hub` and `agent` deployment roles
- global block propagation across connected sensors
- privacy-preserving payload masking before cloud LLM prompts
- external threat intelligence feeds with backend refresh scheduling
- natural-language threat hunting over the SQLite forensics store
- advanced L7 protocol decoders for `HTTP`, `DNS`, `TLS`, `SSH`, `FTP`, `RDP`, `SMB` and `SQL`

## Requirements

- Node.js 22+
- Windows: `Npcap` with WinPcap compatibility enabled
- Linux: `libpcap` plus either `ufw` or `iptables` for firewall enforcement

## Run locally

1. Install dependencies:
   `npm install`
2. Configure backend secrets as environment variables when needed:
   `GEMINI_API_KEY=...`
   `OPENAI_API_KEY=...`
   `ANTHROPIC_API_KEY=...`
   `OPENROUTER_API_KEY=...`
   `GROQ_API_KEY=...`
   `MISTRAL_API_KEY=...`
   `DEEPSEEK_API_KEY=...`
   `XAI_API_KEY=...`
3. Start frontend and backend together:
   `npm run dev`
4. Open the UI and configure:
   `Deployment Mode`: `standalone` for one node, `hub` for central management, `agent` to join a hub
   `Backend Base URL`: `http://localhost:8081`
   `Capture Interface`: your real network adapter
   `Capture Filter`: for example `ip and (tcp or udp)`
   `Payload Privacy Mode`: `Raw payload for local LLMs only` is recommended for LM Studio/Ollama; use `Strict masking` for cloud LLMs
   `Threat Intelligence`: enable feeds only after verifying outbound connectivity from the backend
5. Optional:
   Enable `OS firewall integration` only when the process has the required OS privileges.
   Enable `Live raw feed` only when you need decoded raw packets in the browser.
   Configure `Shared Fleet Token` plus `Hub URL` when this node should join or host a distributed sensor fleet.

## Backend API

- `GET /api/health`
- `GET /api/bootstrap`
- `GET /api/interfaces`
- `GET /api/config`
- `PUT /api/config`
- `GET /api/capture/status`
- `POST /api/capture/start`
- `POST /api/capture/stop`
- `POST /api/capture/replay`
- `GET /api/logs`
- `GET /api/traffic`
- `GET /api/metrics`
- `GET /api/pcap-artifacts`
- `GET /api/pcap-artifacts/:artifactId/download`
- `GET /api/fleet/sensors`
- `GET /api/threat-intel/status`
- `POST /api/threat-intel/refresh`
- `POST /api/forensics/chat`
- WebSocket stream: `ws://localhost:8081/traffic`
- Agent fleet WebSocket: `ws://localhost:8081/fleet/agent`

## Distributed mode

- `standalone`: local capture, analysis, storage and UI against one backend
- `hub`: central dashboard plus aggregation point for remote agents
- `agent`: capture and analyze locally, then forward logs, traffic, artifacts and metrics to a hub over WebSocket

To connect an agent to a hub:

1. Set the hub node to `Deployment Mode = hub`
2. Set the same `Shared Fleet Token` on hub and agent
3. On the agent, set `Deployment Mode = agent`
4. On the agent, set `Hub URL` to the hub backend, for example `http://10.0.0.5:8081`

## Threat intelligence

NetGuard can load remote plain-text, Spamhaus DROP-style or JSON-array feeds into the backend and match IP/CIDR indicators before heuristics and LLM inspection. Feed refresh is configured in `Settings -> Threat Intelligence`.

## Threat hunting

The `Threat Hunt` tab sends a natural-language question to the backend. The backend generates read-only SQLite SQL, executes it against the forensics store and returns a summarized result plus the generated SQL.

## Supported LLM providers

- Gemini
- OpenAI
- Anthropic
- OpenRouter
- Groq
- Mistral
- DeepSeek
- xAI
- LM Studio
- Ollama

Default local endpoints:

- LM Studio: `http://localhost:1234/v1`
- Ollama: `http://localhost:11434`

```

## File: `server/analysisCoordinator.js`  
- Path: `server/analysisCoordinator.js`  
- Size: 3431 Bytes  
- Modified: 2026-03-13 14:29:08 UTC

```javascript
import { LRUCache } from 'lru-cache';
import { analyzeTrafficBatch } from './llmService.js';

export class AnalysisCoordinatorResetError extends Error {
  constructor(message = 'Analysis queue reset.') {
    super(message);
    this.name = 'AnalysisCoordinatorResetError';
    this.code = 'ANALYSIS_QUEUE_RESET';
  }
}

export class AnalysisCoordinator {
  constructor() {
    this.cache = new LRUCache({ max: 5000 });
    this.queues = new Map();
  }

  reset(reason = 'Analysis queue reset.') {
    for (const queue of this.queues.values()) {
      if (queue.timer) {
        clearTimeout(queue.timer);
        queue.timer = null;
      }
      const queuedItems = [...queue.items];
      queue.items = [];
      queuedItems.forEach(item => item.reject(new AnalysisCoordinatorResetError(reason)));
    }
    this.queues.clear();
    this.cache.clear();
  }

  getCacheKey(packet) {
    return `${packet.sourceIp}:${packet.destinationPort}:${packet.protocol}:${packet.l7Protocol}`;
  }

  getQueueKey(config) {
    const providerSettings = config.providerSettings[config.llmProvider];
    return JSON.stringify({
      provider: config.llmProvider,
      model: providerSettings.model,
      baseUrl: providerSettings.baseUrl,
    });
  }

  getOrCreateQueue(queueKey) {
    const existing = this.queues.get(queueKey);
    if (existing) {
      return existing;
    }

    const queue = {
      items: [],
      timer: null,
    };
    this.queues.set(queueKey, queue);
    return queue;
  }

  async analyze(packet, config) {
    const cacheKey = this.getCacheKey(packet);
    const cached = this.cache.get(cacheKey);
    if (cached) {
      return {
        ...cached,
        packet,
        decisionSource: 'cache',
      };
    }

    return new Promise((resolve, reject) => {
      const queueKey = this.getQueueKey(config);
      const queue = this.getOrCreateQueue(queueKey);
      queue.items.push({ packet, config, resolve, reject });

      if (queue.items.length >= config.batchMaxSize) {
        void this.flushQueue(queueKey);
        return;
      }

      if (!queue.timer) {
        queue.timer = setTimeout(() => {
          void this.flushQueue(queueKey);
        }, config.batchWindowMs);
      }
    });
  }

  async flushQueue(queueKey) {
    const queue = this.queues.get(queueKey);
    if (!queue || queue.items.length === 0) {
      return;
    }

    if (queue.timer) {
      clearTimeout(queue.timer);
      queue.timer = null;
    }

    const items = [...queue.items];
    queue.items = [];
    const [firstItem] = items;
    if (!firstItem) {
      return;
    }

    try {
      const results = await analyzeTrafficBatch(items.map(item => item.packet), firstItem.config);
      results.forEach((result, index) => {
        const item = items[index];
        if (!item) {
          return;
        }
        this.cache.set(this.getCacheKey(item.packet), {
          isSuspicious: result.isSuspicious,
          attackType: result.attackType,
          confidence: result.confidence,
          explanation: result.explanation,
          matchedSignals: result.matchedSignals,
          recommendedActionType: result.recommendedActionType,
          recommendedTargetPort: result.recommendedTargetPort,
        }, {
          ttl: item.config.cacheTtlSeconds * 1000,
        });
        item.resolve(result);
      });
    } catch (error) {
      items.forEach(item => item.reject(error));
    }
  }
}

```

## File: `server/captureAgent.js`  
- Path: `server/captureAgent.js`  
- Size: 10572 Bytes  
- Modified: 2026-03-13 13:56:52 UTC

```javascript
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import dgram from 'node:dgram';
import capModule from 'cap';
import { detectLayer7Metadata } from './decoders/index.js';

const { Cap, decoders } = capModule;
const { PROTOCOL } = decoders;

const PACKET_BUFFER_SIZE = 65535;
const LIBPCAP_BUFFER_SIZE = 10 * 1024 * 1024;
const MAX_PAYLOAD_SNIPPET_BYTES = 64;
const PRIMARY_ADDRESS_TIMEOUT_MS = 750;
const DEVICE_DEPRIORITIZATION_PATTERNS = [
  /loopback/i,
  /hyper-v/i,
  /wan miniport/i,
  /wi-fi direct/i,
  /bluetooth/i,
  /virtual/i,
  /npcap loopback/i,
];
const DEVICE_PREFERENCE_PATTERNS = [
  /wi-?fi/i,
  /\bwlan\b/i,
  /ethernet/i,
  /mediatek/i,
  /intel/i,
  /realtek/i,
];

const isLinkLocalAddress = (address) =>
  address.startsWith('169.254.') || address.startsWith('fe80:');

const isPreferredIpv4Address = (address) =>
  /^\d+\.\d+\.\d+\.\d+$/.test(address)
  && !address.startsWith('127.')
  && !address.startsWith('169.254.');

const getLocalAddresses = () =>
  new Set(
    Object.values(os.networkInterfaces())
      .flat()
      .filter(Boolean)
      .map(addressInfo => addressInfo.address)
  );

const bufferToHex = (buffer) => buffer.toString('hex');

const normalizeDevice = (device) => ({
  name: device.name,
  description: device.description || device.name,
  addresses: Array.isArray(device.addresses) ? device.addresses.map(address => address.addr).filter(Boolean) : [],
  loopback: typeof device.flags === 'string' ? device.flags.includes('LOOPBACK') : false,
});

const getAddressCandidates = () => {
  const candidates = [];

  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const addressInfo of addresses ?? []) {
      if (!addressInfo || addressInfo.internal) {
        continue;
      }

      if (addressInfo.family === 'IPv4' && isPreferredIpv4Address(addressInfo.address)) {
        candidates.push(addressInfo.address);
      }
    }
  }

  return [...new Set(candidates)];
};

const scoreDevice = (device, primaryAddress, addressCandidates) => {
  const descriptor = `${device.description} ${device.name}`.toLowerCase();
  const deviceAddresses = new Set(device.addresses.map(address => address.toLowerCase()));
  let score = 0;

  if (primaryAddress && deviceAddresses.has(primaryAddress.toLowerCase())) {
    score += 500;
  }

  for (const candidate of addressCandidates) {
    if (deviceAddresses.has(candidate.toLowerCase())) {
      score += 150;
    }
  }

  if (device.addresses.some(isPreferredIpv4Address)) {
    score += 80;
  }

  if (device.addresses.some(address => isLinkLocalAddress(address.toLowerCase()))) {
    score -= 40;
  }

  if (device.loopback) {
    score -= 250;
  }

  if (DEVICE_PREFERENCE_PATTERNS.some(pattern => pattern.test(descriptor))) {
    score += 60;
  }

  if (DEVICE_DEPRIORITIZATION_PATTERNS.some(pattern => pattern.test(descriptor))) {
    score -= 150;
  }

  return score;
};

const sortDevicesByPreference = (devices, primaryAddress = null) => {
  const addressCandidates = getAddressCandidates();
  return [...devices].sort((leftDevice, rightDevice) => {
    const scoreDelta = scoreDevice(rightDevice, primaryAddress, addressCandidates) - scoreDevice(leftDevice, primaryAddress, addressCandidates);
    if (scoreDelta !== 0) {
      return scoreDelta;
    }
    return leftDevice.description.localeCompare(rightDevice.description);
  });
};

const resolvePrimaryOutboundAddress = async () => {
  const socket = dgram.createSocket('udp4');

  try {
    const connected = await Promise.race([
      new Promise((resolve, reject) => {
        socket.once('error', reject);
        socket.connect(53, '1.1.1.1', resolve);
      }),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Timed out while resolving primary network interface.')), PRIMARY_ADDRESS_TIMEOUT_MS);
      }),
    ]);

    if (connected === undefined) {
      const localSocket = socket.address();
      if (typeof localSocket === 'object' && isPreferredIpv4Address(localSocket.address)) {
        return localSocket.address;
      }
    }
  } catch {
    return null;
  } finally {
    try {
      socket.close();
    } catch {
      // ignore socket close errors during interface probing
    }
  }

  return null;
};

const resolveCaptureDevice = async (preferredDeviceName) => {
  if (preferredDeviceName) {
    return preferredDeviceName;
  }

  const primaryAddress = await resolvePrimaryOutboundAddress();
  if (primaryAddress) {
    try {
      const deviceForPrimaryAddress = Cap.findDevice(primaryAddress);
      if (deviceForPrimaryAddress) {
        return deviceForPrimaryAddress;
      }
    } catch {
      // fall through to heuristic device selection
    }
  }

  const sortedDevices = sortDevicesByPreference(Cap.deviceList().map(normalizeDevice), primaryAddress);
  const [bestDevice] = sortedDevices;
  if (bestDevice?.name) {
    return bestDevice.name;
  }

  return Cap.findDevice();
};

const getDirection = (localAddresses, sourceIp, destinationIp) => {
  if (localAddresses.has(sourceIp)) {
    return 'OUTBOUND';
  }

  if (localAddresses.has(destinationIp)) {
    return 'INBOUND';
  }

  return 'UNKNOWN';
};

const buildPacketFromTransport = ({ basePacket, transportPacket, sourcePort, destinationPort, protocol }) => {
  const payloadBuffer = transportPacket;
  const payloadSnippet = payloadBuffer.subarray(0, MAX_PAYLOAD_SNIPPET_BYTES);
  const packetWithPayload = {
    ...basePacket,
    sourcePort,
    destinationPort,
    protocol,
    payloadSnippet: bufferToHex(payloadSnippet),
    payloadBuffer,
  };
  const l7 = detectLayer7Metadata(packetWithPayload);

  return {
    packet: {
      ...basePacket,
      sourcePort,
      destinationPort,
      protocol,
      payloadSnippet: bufferToHex(payloadSnippet),
      l7Protocol: l7.l7Protocol,
      l7Metadata: l7.l7Metadata,
    },
    rawFrame: transportPacket.__rawFrame ?? null,
  };
};

export const decodePacketFrame = ({
  frame,
  linkType = 'ETHERNET',
  captureDevice = 'unknown',
  timestamp = new Date().toISOString(),
  localAddresses = getLocalAddresses(),
}) => {
  if (linkType !== 'ETHERNET') {
    return null;
  }

  const ethernet = decoders.Ethernet(frame);
  if (ethernet.info.type !== PROTOCOL.ETHERNET.IPV4) {
    return null;
  }

  const ipv4 = decoders.IPV4(frame, ethernet.offset);
  const basePacket = {
    id: randomUUID(),
    sourceIp: ipv4.info.srcaddr,
    destinationIp: ipv4.info.dstaddr,
    timestamp,
    captureDevice,
    size: frame.length,
    direction: getDirection(localAddresses, ipv4.info.srcaddr, ipv4.info.dstaddr),
  };

  if (ipv4.info.protocol === PROTOCOL.IP.TCP) {
    const tcp = decoders.TCP(frame, ipv4.offset);
    const payloadBuffer = frame.subarray(tcp.offset);
    payloadBuffer.__rawFrame = frame;
    const packet = buildPacketFromTransport({
      basePacket,
      transportPacket: payloadBuffer,
      sourcePort: tcp.info.srcport,
      destinationPort: tcp.info.dstport,
      protocol: 'TCP',
    });
    return {
      packet: packet.packet,
      rawFrame: frame,
      originalLength: frame.length,
    };
  }

  if (ipv4.info.protocol === PROTOCOL.IP.UDP) {
    const udp = decoders.UDP(frame, ipv4.offset);
    const payloadBuffer = frame.subarray(udp.offset);
    payloadBuffer.__rawFrame = frame;
    const packet = buildPacketFromTransport({
      basePacket,
      transportPacket: payloadBuffer,
      sourcePort: udp.info.srcport,
      destinationPort: udp.info.dstport,
      protocol: 'UDP',
    });
    return {
      packet: packet.packet,
      rawFrame: frame,
      originalLength: frame.length,
    };
  }

  return null;
};

export class CaptureAgent {
  constructor({ onPacket, onStatus, onError }) {
    this.onPacket = onPacket;
    this.onStatus = onStatus;
    this.onError = onError;
    this.capture = null;
    this.buffer = null;
    this.linkType = null;
    this.activeDevice = null;
    this.activeFilter = '';
    this.startedAt = null;
    this.replayActive = false;
    this.localAddresses = getLocalAddresses();
  }

  listInterfaces() {
    try {
      return sortDevicesByPreference(Cap.deviceList().map(normalizeDevice));
    } catch (error) {
      this.onError(error instanceof Error ? error : new Error('Failed to enumerate capture devices.'));
      return [];
    }
  }

  getStatus(clientCount = 0) {
    return {
      running: Boolean(this.capture),
      activeDevice: this.activeDevice,
      activeFilter: this.activeFilter,
      startedAt: this.startedAt,
      clientCount,
      replayActive: this.replayActive,
    };
  }

  setReplayActive(active, clientCount = 0) {
    this.replayActive = active;
    this.onStatus(this.getStatus(clientCount));
  }

  async start({ deviceName, filter }, clientCount = 0) {
    this.stop(clientCount, false);

    this.localAddresses = getLocalAddresses();

    const selectedDevice = await resolveCaptureDevice(deviceName);
    if (!selectedDevice) {
      throw new Error('No compatible capture device found. Install Npcap/WinPcap compatibility on Windows or libpcap on Linux.');
    }

    this.capture = new Cap();
    this.buffer = Buffer.alloc(PACKET_BUFFER_SIZE);
    this.activeDevice = selectedDevice;
    this.activeFilter = filter;
    this.startedAt = new Date().toISOString();

    this.linkType = this.capture.open(selectedDevice, filter, LIBPCAP_BUFFER_SIZE, this.buffer);
    if (typeof this.capture.setMinBytes === 'function') {
      this.capture.setMinBytes(0);
    }

    this.capture.on('packet', nbytes => {
      try {
        const frame = Buffer.from(this.buffer.subarray(0, nbytes));
        const decodedPacket = decodePacketFrame({
          frame,
          linkType: this.linkType,
          captureDevice: this.activeDevice || 'unknown',
          timestamp: new Date().toISOString(),
          localAddresses: this.localAddresses,
        });

        if (decodedPacket) {
          this.onPacket(decodedPacket);
        }
      } catch (error) {
        this.onError(error instanceof Error ? error : new Error('Failed to decode captured packet.'));
      }
    });

    this.onStatus(this.getStatus(clientCount));
    return this.getStatus(clientCount);
  }

  stop(clientCount = 0, emitStatus = true) {
    if (this.capture) {
      this.capture.close();
      this.capture = null;
    }

    this.buffer = null;
    this.linkType = null;
    this.activeDevice = null;
    this.activeFilter = '';
    this.startedAt = null;

    if (emitStatus) {
      this.onStatus(this.getStatus(clientCount));
    }

    return this.getStatus(clientCount);
  }
}

```

## File: `server/configStore.js`  
- Path: `server/configStore.js`  
- Size: 4749 Bytes  
- Modified: 2026-03-13 12:58:16 UTC

```javascript
import crypto from 'node:crypto';
import { z } from 'zod';
import { createDefaultServerConfig, createDefaultProviderSettings, PROVIDER_DEFINITIONS } from './defaultConfig.js';

const providerIds = PROVIDER_DEFINITIONS.map(definition => definition.id);

const providerSettingsSchema = z.record(
  z.string(),
  z.object({
    model: z.string().trim().min(1),
    baseUrl: z.string().trim().min(1),
    apiKey: z.string().optional().default(''),
  })
);

const webhookSchema = z.object({
  id: z.string().min(1).default(() => crypto.randomUUID()),
  name: z.string().trim().min(1),
  provider: z.enum(['generic', 'slack', 'discord', 'teams']),
  url: z.string().trim().url(),
  enabled: z.boolean(),
});

const threatIntelSourceSchema = z.object({
  id: z.string().min(1).default(() => crypto.randomUUID()),
  name: z.string().trim().min(1),
  url: z.string().trim().url(),
  format: z.enum(['plain', 'spamhaus_drop', 'json_array']),
  enabled: z.boolean(),
});

const customRuleConditionSchema = z.object({
  id: z.string().min(1).default(() => crypto.randomUUID()),
  field: z.enum([
    'sourceIp',
    'destinationIp',
    'sourcePort',
    'destinationPort',
    'protocol',
    'direction',
    'size',
    'l7Protocol',
    'payloadSnippet',
    'l7.host',
    'l7.path',
    'l7.userAgent',
    'l7.dnsQuery',
    'l7.sni',
    'l7.sshBanner',
    'l7.ftpCommand',
    'l7.rdpCookie',
    'l7.smbCommand',
    'l7.sqlOperation',
  ]),
  operator: z.enum([
    'equals',
    'not_equals',
    'greater_than',
    'less_than',
    'contains',
    'starts_with',
    'in_cidr',
    'not_in_cidr',
    'in_list',
    'not_in_list',
  ]),
  value: z.string().trim().min(1),
});

const customRuleSchema = z.object({
  id: z.string().min(1).default(() => crypto.randomUUID()),
  name: z.string().trim().min(1),
  enabled: z.boolean(),
  matchMode: z.enum(['all', 'any']),
  conditions: z.array(customRuleConditionSchema).min(1),
  outcome: z.object({
    actionType: z.enum(['REDIRECT', 'BLOCK', 'ALLOW']),
    attackType: z.enum(['port_scan', 'brute_force', 'malicious_payload', 'ddos', 'none', 'other']),
    confidence: z.number().min(0).max(1),
    explanation: z.string().trim().min(1),
    targetPort: z.number().int().positive().max(65535).optional(),
    needsDeepInspection: z.boolean(),
  }),
});

const serverConfigurationSchema = z.object({
  llmProvider: z.enum(providerIds),
  providerSettings: providerSettingsSchema,
  deploymentMode: z.enum(['standalone', 'hub', 'agent']),
  sensorId: z.string().trim().min(1),
  sensorName: z.string().trim().min(1),
  hubUrl: z.string().trim().optional().default(''),
  fleetSharedToken: z.string().optional().default(''),
  globalBlockPropagationEnabled: z.boolean(),
  captureInterface: z.string().optional().default(''),
  captureFilter: z.string().trim().min(1),
  cacheTtlSeconds: z.number().int().min(1).max(3600),
  batchWindowMs: z.number().int().min(100).max(30000),
  batchMaxSize: z.number().int().min(1).max(200),
  securePort: z.number().int().min(1).max(65535),
  monitoringPorts: z.array(z.number().int().min(1).max(65535)),
  detectionThreshold: z.number().min(0).max(1),
  autoBlockThreats: z.boolean(),
  liveRawFeedEnabled: z.boolean(),
  firewallIntegrationEnabled: z.boolean(),
  pcapBufferSize: z.number().int().min(1).max(100),
  payloadMaskingMode: z.enum(['strict', 'raw_local_only']),
  threatIntelEnabled: z.boolean(),
  threatIntelRefreshHours: z.number().int().min(1).max(168),
  threatIntelAutoBlock: z.boolean(),
  threatIntelSources: z.array(threatIntelSourceSchema),
  blockedIps: z.array(z.string().trim()),
  blockedPorts: z.array(z.number().int().min(1).max(65535)),
  exemptPorts: z.array(z.number().int().min(1).max(65535)),
  webhookIntegrations: z.array(webhookSchema),
  customRules: z.array(customRuleSchema),
});

export const sanitizeConfigurationForClient = (configuration) => ({
  ...configuration,
  fleetSharedToken: '',
  providerSettings: Object.fromEntries(
    Object.entries(configuration.providerSettings).map(([providerId, settings]) => [
      providerId,
      {
        ...settings,
        apiKey: '',
      },
    ])
  ),
});

export const normalizeServerConfiguration = (inputConfiguration) => {
  const defaults = createDefaultServerConfig();
  const parsedConfiguration = serverConfigurationSchema.parse({
    ...defaults,
    ...inputConfiguration,
    providerSettings: {
      ...createDefaultProviderSettings(),
      ...(inputConfiguration?.providerSettings ?? {}),
    },
  });

  for (const providerId of providerIds) {
    if (!parsedConfiguration.providerSettings[providerId]) {
      parsedConfiguration.providerSettings[providerId] = createDefaultProviderSettings()[providerId];
    }
  }

  return parsedConfiguration;
};

```

## File: `server/dataScrubber.js`  
- Path: `server/dataScrubber.js`  
- Size: 4242 Bytes  
- Modified: 2026-03-13 12:59:42 UTC

```javascript
const SENSITIVE_PATTERNS = [
  {
    label: 'credit_card',
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: '[REDACTED_CREDIT_CARD]',
  },
  {
    label: 'email',
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: '[REDACTED_EMAIL]',
  },
  {
    label: 'bearer_token',
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi,
    replacement: 'Bearer [REDACTED_TOKEN]',
  },
  {
    label: 'basic_auth',
    pattern: /\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]+\b/gi,
    replacement: 'Authorization: Basic [REDACTED_CREDENTIALS]',
  },
  {
    label: 'cookie',
    pattern: /\b(?:session|sessionid|csrftoken|token|auth|jwt|refresh_token)=([^;\s]+)/gi,
    replacement: (_match, token) => `[REDACTED_COOKIE:${token.length}]`,
  },
  {
    label: 'password',
    pattern: /\b(password|passwd|pwd)\s*[:=]\s*([^\s&]+)/gi,
    replacement: '$1=[REDACTED_PASSWORD]',
  },
  {
    label: 'api_key',
    pattern: /\b(api[_-]?key|secret|client_secret)\s*[:=]\s*([^\s&]+)/gi,
    replacement: '$1=[REDACTED_SECRET]',
  },
];

const decodeHexPayload = (hexValue) => {
  if (!hexValue || typeof hexValue !== 'string') {
    return '';
  }

  try {
    const bytes = new Uint8Array(
      hexValue.match(/.{1,2}/g)?.map(byte => Number.parseInt(byte, 16)).filter(byte => !Number.isNaN(byte)) ?? []
    );
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
};

const calculateEntropy = (value) => {
  if (!value) {
    return 0;
  }

  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
};

const redactHighEntropyTokens = (input) => {
  let redactions = 0;
  const output = input.replace(/\b[A-Za-z0-9+/=_\-]{20,}\b/g, token => {
    if (calculateEntropy(token) >= 3.5) {
      redactions += 1;
      return `[REDACTED_TOKEN:${token.length}]`;
    }
    return token;
  });

  return { output, redactions };
};

export const scrubText = (input) => {
  if (!input) {
    return {
      text: '',
      redactions: [],
      redactionCount: 0,
    };
  }

  let output = input;
  const redactions = [];

  for (const matcher of SENSITIVE_PATTERNS) {
    let matched = false;
    output = output.replace(matcher.pattern, (...args) => {
      matched = true;
      if (typeof matcher.replacement === 'function') {
        return matcher.replacement(...args);
      }
      return matcher.replacement;
    });
    if (matched) {
      redactions.push(matcher.label);
    }
  }

  const entropyRedaction = redactHighEntropyTokens(output);
  output = entropyRedaction.output;
  if (entropyRedaction.redactions > 0) {
    redactions.push('high_entropy_token');
  }

  return {
    text: output,
    redactions,
    redactionCount: redactions.length + entropyRedaction.redactions,
  };
};

export const scrubMetadata = (metadata) => {
  const nextMetadata = {};
  const redactions = new Set();

  for (const [key, value] of Object.entries(metadata ?? {})) {
    const scrubbed = scrubText(String(value ?? ''));
    nextMetadata[key] = scrubbed.text;
    scrubbed.redactions.forEach(redaction => redactions.add(`${key}:${redaction}`));
  }

  return {
    metadata: nextMetadata,
    redactions: [...redactions],
  };
};

export const preparePacketForLlm = (packet, config, providerDefinition) => {
  const decodedPayload = decodeHexPayload(packet.payloadSnippet);
  const shouldScrub = config.payloadMaskingMode === 'strict' || !providerDefinition.local;

  if (!shouldScrub) {
    return {
      payloadText: decodedPayload,
      payloadHex: packet.payloadSnippet,
      l7Metadata: packet.l7Metadata,
      masking: {
        applied: false,
        redactions: [],
      },
    };
  }

  const scrubbedPayload = scrubText(decodedPayload);
  const scrubbedMetadata = scrubMetadata(packet.l7Metadata);

  return {
    payloadText: scrubbedPayload.text,
    payloadHex: '',
    l7Metadata: scrubbedMetadata.metadata,
    masking: {
      applied: true,
      redactions: [...new Set([...scrubbedPayload.redactions, ...scrubbedMetadata.redactions])],
    },
  };
};

```

## File: `server/db.js`  
- Path: `server/db.js`  
- Size: 19411 Bytes  
- Modified: 2026-03-13 13:22:20 UTC

```javascript
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { createDefaultServerConfig } from './defaultConfig.js';
import { normalizeServerConfiguration, sanitizeConfigurationForClient } from './configStore.js';

const dataDirectory = path.resolve(process.cwd(), 'data');
const pcapDirectory = path.join(dataDirectory, 'pcap');
const replayDirectory = path.join(dataDirectory, 'replay');
const databasePath = path.join(dataDirectory, 'netguard.db');

fs.mkdirSync(dataDirectory, { recursive: true });
fs.mkdirSync(pcapDirectory, { recursive: true });
fs.mkdirSync(replayDirectory, { recursive: true });

const db = new Database(databasePath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);

  CREATE TABLE IF NOT EXISTS traffic_events (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    packet_timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    is_suspicious INTEGER NOT NULL,
    decision_source TEXT NOT NULL,
    action TEXT NOT NULL,
    action_type TEXT NOT NULL,
    explanation TEXT NOT NULL,
    firewall_applied INTEGER NOT NULL,
    pcap_artifact_id TEXT,
    packet_json TEXT NOT NULL,
    matched_signals_json TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_traffic_created_at ON traffic_events (created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_traffic_attack_type ON traffic_events (attack_type);

  CREATE TABLE IF NOT EXISTS pcap_artifacts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    explanation TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    threat_event_id TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_pcap_created_at ON pcap_artifacts (created_at DESC);

  CREATE TABLE IF NOT EXISTS sensors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL,
    hub_url TEXT,
    connected INTEGER NOT NULL,
    capture_running INTEGER NOT NULL,
    last_seen_at TEXT,
    last_event_at TEXT,
    packets_processed INTEGER NOT NULL DEFAULT 0,
    threats_detected INTEGER NOT NULL DEFAULT 0,
    blocked_decisions INTEGER NOT NULL DEFAULT 0,
    local INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_sensors_last_seen ON sensors (last_seen_at DESC);

  CREATE TABLE IF NOT EXISTS threat_intel_indicators (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    label TEXT,
    confidence REAL NOT NULL DEFAULT 1,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (indicator, source_id)
  );
  CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel_indicators (source_id);

  CREATE TABLE IF NOT EXISTS forensics_queries (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    question TEXT NOT NULL,
    sql_query TEXT NOT NULL,
    summary TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    sensor_id TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_forensics_created_at ON forensics_queries (created_at DESC);
`);

const ensureColumn = (tableName, columnName, definition) => {
  const existingColumns = db.prepare(`PRAGMA table_info(${tableName})`).all();
  if (!existingColumns.some(column => column.name === columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
};

ensureColumn('logs', 'sensor_id', 'TEXT');
ensureColumn('logs', 'sensor_name', 'TEXT');
ensureColumn('traffic_events', 'sensor_id', 'TEXT');
ensureColumn('traffic_events', 'sensor_name', 'TEXT');
ensureColumn('pcap_artifacts', 'sensor_id', 'TEXT');
ensureColumn('pcap_artifacts', 'sensor_name', 'TEXT');

const configRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('activeConfig');
if (!configRow) {
  const defaultConfiguration = normalizeServerConfiguration(createDefaultServerConfig());
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('activeConfig', JSON.stringify(defaultConfiguration));
}

const serialize = (value) => JSON.stringify(value ?? null);
const deserialize = (value, fallback = null) => {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
};

const buildSensorFilterSql = (sensorId, columnName) => sensorId ? `WHERE ${columnName} = @sensorId` : '';

const mapTrafficRow = row => ({
  id: row.id,
  action: row.action,
  actionType: row.action_type,
  attackType: row.attack_type,
  confidence: row.confidence,
  createdAt: row.created_at,
  decisionSource: row.decision_source,
  explanation: row.explanation,
  firewallApplied: Boolean(row.firewall_applied),
  isSuspicious: Boolean(row.is_suspicious),
  matchedSignals: deserialize(row.matched_signals_json, []),
  packet: deserialize(row.packet_json, {}),
  pcapArtifactId: row.pcap_artifact_id,
  sensorId: row.sensor_id ?? deserialize(row.packet_json, {})?.sensorId ?? 'unknown',
  sensorName: row.sensor_name ?? deserialize(row.packet_json, {})?.sensorName ?? 'Unknown Sensor',
});

export const directories = {
  dataDirectory,
  pcapDirectory,
  replayDirectory,
  databasePath,
};

export const getServerConfiguration = () => {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('activeConfig');
  const configuration = normalizeServerConfiguration(deserialize(row?.value, createDefaultServerConfig()));
  return configuration;
};

export const getClientConfiguration = () => sanitizeConfigurationForClient(getServerConfiguration());

export const saveServerConfiguration = (configuration) => {
  const normalizedConfiguration = normalizeServerConfiguration(configuration);
  db.prepare('REPLACE INTO settings (key, value) VALUES (?, ?)').run('activeConfig', JSON.stringify(normalizedConfiguration));
  return normalizedConfiguration;
};

export const insertLogEntry = (entry) => {
  db.prepare(`
    INSERT OR REPLACE INTO logs (id, timestamp, level, message, details_json, sensor_id, sensor_name)
    VALUES (@id, @timestamp, @level, @message, @detailsJson, @sensorId, @sensorName)
  `).run({
    id: entry.id,
    timestamp: entry.timestamp,
    level: entry.level,
    message: entry.message,
    detailsJson: serialize(entry.details),
    sensorId: entry.sensorId ?? null,
    sensorName: entry.sensorName ?? null,
  });
  return entry;
};

export const listRecentLogs = (limit = 500, sensorId = null) =>
  db.prepare(`
    SELECT id, timestamp, level, message, details_json AS detailsJson, sensor_id AS sensorId, sensor_name AS sensorName
    FROM logs
    ${buildSensorFilterSql(sensorId, 'sensor_id')}
    ORDER BY timestamp DESC
    LIMIT @limit
  `).all({ limit, sensorId }).map(row => ({
    id: row.id,
    timestamp: row.timestamp,
    level: row.level,
    message: row.message,
    details: deserialize(row.detailsJson, undefined),
    sensorId: row.sensorId ?? undefined,
    sensorName: row.sensorName ?? undefined,
  }));

export const insertTrafficEvent = (entry) => {
  db.prepare(`
    INSERT OR REPLACE INTO traffic_events (
      id, created_at, packet_timestamp, source_ip, destination_ip, source_port, destination_port,
      protocol, attack_type, confidence, is_suspicious, decision_source, action, action_type,
      explanation, firewall_applied, pcap_artifact_id, packet_json, matched_signals_json, sensor_id, sensor_name
    ) VALUES (
      @id, @createdAt, @packetTimestamp, @sourceIp, @destinationIp, @sourcePort, @destinationPort,
      @protocol, @attackType, @confidence, @isSuspicious, @decisionSource, @action, @actionType,
      @explanation, @firewallApplied, @pcapArtifactId, @packetJson, @matchedSignalsJson, @sensorId, @sensorName
    )
  `).run({
    id: entry.id,
    createdAt: entry.createdAt,
    packetTimestamp: entry.packet.timestamp,
    sourceIp: entry.packet.sourceIp,
    destinationIp: entry.packet.destinationIp,
    sourcePort: entry.packet.sourcePort,
    destinationPort: entry.packet.destinationPort,
    protocol: entry.packet.protocol,
    attackType: entry.attackType,
    confidence: entry.confidence,
    isSuspicious: entry.isSuspicious ? 1 : 0,
    decisionSource: entry.decisionSource,
    action: entry.action,
    actionType: entry.actionType,
    explanation: entry.explanation,
    firewallApplied: entry.firewallApplied ? 1 : 0,
    pcapArtifactId: entry.pcapArtifactId ?? null,
    packetJson: serialize(entry.packet),
    matchedSignalsJson: serialize(entry.matchedSignals),
    sensorId: entry.sensorId ?? entry.packet.sensorId ?? null,
    sensorName: entry.sensorName ?? entry.packet.sensorName ?? null,
  });
  return entry;
};

export const listRecentTrafficEvents = (limit = 100, sensorId = null) =>
  db.prepare(`
    SELECT *
    FROM traffic_events
    ${buildSensorFilterSql(sensorId, 'sensor_id')}
    ORDER BY created_at DESC
    LIMIT @limit
  `).all({ limit, sensorId }).map(mapTrafficRow);

export const getTrafficCounters = (sensorId = null) => {
  const thresholdDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const packetCountRow = db.prepare(`
    SELECT COUNT(*) AS count
    FROM traffic_events
    ${buildSensorFilterSql(sensorId, 'sensor_id')}
  `).get({ sensorId });
  const threatCountRow = db.prepare(`
    SELECT COUNT(*) AS count
    FROM traffic_events
    ${sensorId ? 'WHERE sensor_id = @sensorId AND is_suspicious = 1 AND created_at >= @thresholdDate' : 'WHERE is_suspicious = 1 AND created_at >= @thresholdDate'}
  `).get({ sensorId, thresholdDate });
  const blockedCountRow = db.prepare(`
    SELECT COUNT(*) AS count
    FROM traffic_events
    ${sensorId ? "WHERE sensor_id = @sensorId AND action_type = 'BLOCK'" : "WHERE action_type = 'BLOCK'"}
  `).get({ sensorId });

  return {
    packetsProcessed: Number(packetCountRow?.count ?? 0),
    threatsDetected: Number(threatCountRow?.count ?? 0),
    blockedDecisions: Number(blockedCountRow?.count ?? 0),
  };
};

export const listTrafficMetrics = (hours = 24, bucketMinutes = 15, sensorId = null) => {
  const thresholdDate = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
  const rows = db.prepare(`
    SELECT created_at AS createdAt, is_suspicious AS isSuspicious, action_type AS actionType
    FROM traffic_events
    ${sensorId ? 'WHERE created_at >= @thresholdDate AND sensor_id = @sensorId' : 'WHERE created_at >= @thresholdDate'}
    ORDER BY created_at ASC
  `).all({ thresholdDate, sensorId });

  const bucketSizeMs = bucketMinutes * 60 * 1000;
  const buckets = new Map();

  for (const row of rows) {
    const timestampMs = Date.parse(row.createdAt);
    const bucketStart = new Date(Math.floor(timestampMs / bucketSizeMs) * bucketSizeMs).toISOString();
    const existingBucket = buckets.get(bucketStart) ?? {
      bucketStart,
      trafficCount: 0,
      threatCount: 0,
      blockedCount: 0,
    };

    existingBucket.trafficCount += 1;
    if (Boolean(row.isSuspicious)) {
      existingBucket.threatCount += 1;
    }
    if (row.actionType === 'BLOCK') {
      existingBucket.blockedCount += 1;
    }

    buckets.set(bucketStart, existingBucket);
  }

  return [...buckets.values()];
};

export const insertPcapArtifact = (artifact) => {
  db.prepare(`
    INSERT OR REPLACE INTO pcap_artifacts (
      id, created_at, file_name, file_path, attack_type, source_ip, packet_count, explanation, bytes, threat_event_id, sensor_id, sensor_name
    ) VALUES (
      @id, @createdAt, @fileName, @filePath, @attackType, @sourceIp, @packetCount, @explanation, @bytes, @threatEventId, @sensorId, @sensorName
    )
  `).run({
    ...artifact,
    sensorId: artifact.sensorId ?? null,
    sensorName: artifact.sensorName ?? null,
  });
  return artifact;
};

export const listPcapArtifacts = (limit = 50, sensorId = null) =>
  db.prepare(`
    SELECT id, created_at AS createdAt, file_name AS fileName, attack_type AS attackType,
           source_ip AS sourceIp, packet_count AS packetCount, explanation, bytes, sensor_id AS sensorId, sensor_name AS sensorName
    FROM pcap_artifacts
    ${buildSensorFilterSql(sensorId, 'sensor_id')}
    ORDER BY created_at DESC
    LIMIT @limit
  `).all({ limit, sensorId }).map(row => ({
    ...row,
    sensorId: row.sensorId ?? 'unknown',
    sensorName: row.sensorName ?? 'Unknown Sensor',
  }));

export const getPcapArtifactById = (artifactId) =>
  db.prepare(`
    SELECT id, created_at AS createdAt, file_name AS fileName, file_path AS filePath, attack_type AS attackType,
           source_ip AS sourceIp, packet_count AS packetCount, explanation, bytes, threat_event_id AS threatEventId,
           sensor_id AS sensorId, sensor_name AS sensorName
    FROM pcap_artifacts
    WHERE id = ?
  `).get(artifactId);

export const upsertSensor = (sensor) => {
  db.prepare(`
    INSERT INTO sensors (
      id, name, mode, hub_url, connected, capture_running, last_seen_at, last_event_at,
      packets_processed, threats_detected, blocked_decisions, local, metadata_json
    ) VALUES (
      @id, @name, @mode, @hubUrl, @connected, @captureRunning, @lastSeenAt, @lastEventAt,
      @packetsProcessed, @threatsDetected, @blockedDecisions, @local, @metadataJson
    )
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      mode = excluded.mode,
      hub_url = excluded.hub_url,
      connected = excluded.connected,
      capture_running = excluded.capture_running,
      last_seen_at = excluded.last_seen_at,
      last_event_at = excluded.last_event_at,
      packets_processed = excluded.packets_processed,
      threats_detected = excluded.threats_detected,
      blocked_decisions = excluded.blocked_decisions,
      local = excluded.local,
      metadata_json = excluded.metadata_json
  `).run({
    id: sensor.id,
    name: sensor.name,
    mode: sensor.mode,
    hubUrl: sensor.hubUrl ?? null,
    connected: sensor.connected ? 1 : 0,
    captureRunning: sensor.captureRunning ? 1 : 0,
    lastSeenAt: sensor.lastSeenAt ?? null,
    lastEventAt: sensor.lastEventAt ?? null,
    packetsProcessed: sensor.packetsProcessed ?? 0,
    threatsDetected: sensor.threatsDetected ?? 0,
    blockedDecisions: sensor.blockedDecisions ?? 0,
    local: sensor.local ? 1 : 0,
    metadataJson: serialize(sensor.metadata ?? {}),
  });
  return sensor;
};

export const markSensorDisconnected = (sensorId) => {
  db.prepare(`
    UPDATE sensors
    SET connected = 0
    WHERE id = ?
  `).run(sensorId);
};

export const deleteSensor = (sensorId) => {
  db.prepare('DELETE FROM sensors WHERE id = ?').run(sensorId);
};

export const listSensors = () =>
  db.prepare(`
    SELECT id, name, mode, hub_url AS hubUrl, connected, capture_running AS captureRunning, last_seen_at AS lastSeenAt,
           last_event_at AS lastEventAt, packets_processed AS packetsProcessed, threats_detected AS threatsDetected,
           blocked_decisions AS blockedDecisions, local
    FROM sensors
    ORDER BY local DESC, name ASC
  `).all().map(row => ({
    id: row.id,
    name: row.name,
    mode: row.mode,
    hubUrl: row.hubUrl,
    connected: Boolean(row.connected),
    captureRunning: Boolean(row.captureRunning),
    lastSeenAt: row.lastSeenAt,
    lastEventAt: row.lastEventAt,
    packetsProcessed: Number(row.packetsProcessed ?? 0),
    threatsDetected: Number(row.threatsDetected ?? 0),
    blockedDecisions: Number(row.blockedDecisions ?? 0),
    local: Boolean(row.local),
  }));

export const replaceThreatIntelIndicators = (source, indicators) => {
  const deleteStatement = db.prepare('DELETE FROM threat_intel_indicators WHERE source_id = ?');
  const insertStatement = db.prepare(`
    INSERT OR REPLACE INTO threat_intel_indicators (
      indicator, indicator_type, source_id, source_name, label, confidence, metadata_json, created_at
    ) VALUES (
      @indicator, @indicatorType, @sourceId, @sourceName, @label, @confidence, @metadataJson, @createdAt
    )
  `);

  const transaction = db.transaction(() => {
    deleteStatement.run(source.id);
    indicators.forEach(indicator => {
      insertStatement.run({
        indicator: indicator.indicator,
        indicatorType: indicator.indicatorType,
        sourceId: source.id,
        sourceName: source.name,
        label: indicator.label ?? null,
        confidence: indicator.confidence ?? 1,
        metadataJson: serialize(indicator.metadata ?? {}),
        createdAt: indicator.createdAt ?? new Date().toISOString(),
      });
    });
  });

  transaction();
};

export const listThreatIntelIndicators = () =>
  db.prepare(`
    SELECT indicator, indicator_type AS indicatorType, source_id AS sourceId, source_name AS sourceName,
           label, confidence, metadata_json AS metadataJson, created_at AS createdAt
    FROM threat_intel_indicators
  `).all().map(row => ({
    indicator: row.indicator,
    indicatorType: row.indicatorType,
    sourceId: row.sourceId,
    sourceName: row.sourceName,
    label: row.label,
    confidence: row.confidence,
    metadata: deserialize(row.metadataJson, {}),
    createdAt: row.createdAt,
  }));

export const insertForensicsQuery = (queryRecord) => {
  db.prepare(`
    INSERT OR REPLACE INTO forensics_queries (id, created_at, question, sql_query, summary, row_count, sensor_id)
    VALUES (@id, @createdAt, @question, @sqlQuery, @summary, @rowCount, @sensorId)
  `).run({
    id: queryRecord.id,
    createdAt: queryRecord.createdAt,
    question: queryRecord.question,
    sqlQuery: queryRecord.sql,
    summary: queryRecord.summary,
    rowCount: queryRecord.rows.length,
    sensorId: queryRecord.sensorId ?? null,
  });
  return queryRecord;
};

export const listRecentForensicsQueries = (limit = 20) =>
  db.prepare(`
    SELECT id, created_at AS createdAt, question, sql_query AS sql, summary, row_count AS rowCount, sensor_id AS sensorId
    FROM forensics_queries
    ORDER BY created_at DESC
    LIMIT ?
  `).all(limit);

export const executeReadOnlyQuery = (sql) => db.prepare(sql).all();

export const getForensicsSchema = () => ({
  tables: [
    {
      name: 'traffic_events',
      columns: [
        'id',
        'created_at',
        'packet_timestamp',
        'source_ip',
        'destination_ip',
        'source_port',
        'destination_port',
        'protocol',
        'attack_type',
        'confidence',
        'is_suspicious',
        'decision_source',
        'action',
        'action_type',
        'explanation',
        'firewall_applied',
        'pcap_artifact_id',
        'sensor_id',
        'sensor_name',
      ],
    },
    {
      name: 'logs',
      columns: ['id', 'timestamp', 'level', 'message', 'sensor_id', 'sensor_name'],
    },
    {
      name: 'pcap_artifacts',
      columns: ['id', 'created_at', 'file_name', 'attack_type', 'source_ip', 'packet_count', 'bytes', 'sensor_id', 'sensor_name'],
    },
    {
      name: 'sensors',
      columns: ['id', 'name', 'mode', 'connected', 'capture_running', 'last_seen_at', 'last_event_at'],
    },
  ],
});

```

## File: `server/decoders/dns.js`  
- Path: `server/decoders/dns.js`  
- Size: 935 Bytes  
- Modified: 2026-03-13 13:00:02 UTC

```javascript
import { hasPort, parseDnsName } from './helpers.js';

export const dnsDecoder = {
  id: 'DNS',
  matches(packet) {
    return hasPort(packet, [53]);
  },
  decode(packet) {
    const dnsPayload = packet.protocol === 'TCP' ? packet.payloadBuffer.subarray(2) : packet.payloadBuffer;
    if (dnsPayload.length < 12) {
      return null;
    }

    const flags = dnsPayload.readUInt16BE(2);
    const questionCount = dnsPayload.readUInt16BE(4);
    const isResponse = Boolean(flags & 0x8000);
    if (questionCount < 1 || isResponse) {
      return null;
    }

    const parsedName = parseDnsName(dnsPayload, 12);
    if (!parsedName || parsedName.nextOffset + 4 > dnsPayload.length) {
      return null;
    }

    const recordType = dnsPayload.readUInt16BE(parsedName.nextOffset);
    return {
      l7Protocol: 'DNS',
      l7Metadata: {
        dnsQuery: parsedName.name,
        dnsType: String(recordType),
      },
    };
  },
};

```

## File: `server/decoders/ftp.js`  
- Path: `server/decoders/ftp.js`  
- Size: 906 Bytes  
- Modified: 2026-03-13 13:00:24 UTC

```javascript
import { hasPort, payloadToUtf8 } from './helpers.js';

const FTP_COMMANDS = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'CWD', 'QUIT', 'AUTH', 'PORT', 'PASV', 'EPSV'];

export const ftpDecoder = {
  id: 'FTP',
  matches(packet) {
    return hasPort(packet, [21]);
  },
  decode(packet) {
    const payloadText = payloadToUtf8(packet.payloadBuffer);
    const firstLine = payloadText.split('\r\n')[0]?.trim() ?? '';
    if (!firstLine) {
      return null;
    }

    const command = firstLine.split(' ')[0] ?? '';
    const isCommand = FTP_COMMANDS.includes(command);
    const isStatus = /^\d{3}\b/.test(command);
    if (!isCommand && !isStatus) {
      return null;
    }

    return {
      l7Protocol: 'FTP',
      l7Metadata: {
        ftpCommand: isCommand ? command : '',
        ftpStatus: isStatus ? command : '',
        ftpMessage: firstLine.slice(command.length).trim(),
      },
    };
  },
};

```

## File: `server/decoders/helpers.js`  
- Path: `server/decoders/helpers.js`  
- Size: 933 Bytes  
- Modified: 2026-03-13 12:59:50 UTC

```javascript
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'];

export const payloadToUtf8 = (payload) => {
  try {
    return payload.toString('utf8');
  } catch {
    return '';
  }
};

export const getAsciiLine = (payload) => payloadToUtf8(payload).split('\r\n')[0] ?? '';

export const hasPort = (packet, ports) => ports.includes(packet.destinationPort) || ports.includes(packet.sourcePort);

export const parseDnsName = (payload, startOffset) => {
  const labels = [];
  let cursor = startOffset;

  while (cursor < payload.length) {
    const length = payload[cursor];
    if (length === 0) {
      return {
        name: labels.join('.'),
        nextOffset: cursor + 1,
      };
    }

    if ((length & 0xc0) === 0xc0) {
      return null;
    }

    cursor += 1;
    labels.push(payload.subarray(cursor, cursor + length).toString('utf8'));
    cursor += length;
  }

  return null;
};

```

## File: `server/decoders/http.js`  
- Path: `server/decoders/http.js`  
- Size: 1247 Bytes  
- Modified: 2026-03-13 12:59:56 UTC

```javascript
import { HTTP_METHODS, hasPort, payloadToUtf8 } from './helpers.js';

export const httpDecoder = {
  id: 'HTTP',
  matches(packet) {
    return hasPort(packet, [80, 8080, 8000]);
  },
  decode(packet) {
    const payloadText = payloadToUtf8(packet.payloadBuffer);
    if (!payloadText) {
      return null;
    }

    const firstLine = payloadText.split('\r\n')[0] ?? '';
    const isHttp = HTTP_METHODS.some(method => firstLine.startsWith(`${method} `)) || firstLine.startsWith('HTTP/');
    if (!isHttp) {
      return null;
    }

    const hostMatch = payloadText.match(/^Host:\s*(.+)$/im);
    const userAgentMatch = payloadText.match(/^User-Agent:\s*(.+)$/im);
    const contentTypeMatch = payloadText.match(/^Content-Type:\s*(.+)$/im);
    const authHeaderMatch = payloadText.match(/^Authorization:\s*(.+)$/im);
    const firstLineParts = firstLine.split(' ');

    return {
      l7Protocol: 'HTTP',
      l7Metadata: {
        method: firstLineParts[0] || '',
        path: firstLineParts[1] || '',
        host: hostMatch?.[1]?.trim() || '',
        userAgent: userAgentMatch?.[1]?.trim() || '',
        contentType: contentTypeMatch?.[1]?.trim() || '',
        authorization: authHeaderMatch?.[1]?.trim() || '',
      },
    };
  },
};

```

## File: `server/decoders/index.js`  
- Path: `server/decoders/index.js`  
- Size: 947 Bytes  
- Modified: 2026-03-13 13:00:52 UTC

```javascript
import { dnsDecoder } from './dns.js';
import { ftpDecoder } from './ftp.js';
import { httpDecoder } from './http.js';
import { rdpDecoder } from './rdp.js';
import { smbDecoder } from './smb.js';
import { sqlDecoder } from './sql.js';
import { sshDecoder } from './ssh.js';
import { tlsDecoder } from './tls.js';

const fallbackResult = {
  l7Protocol: 'UNKNOWN',
  l7Metadata: {},
};

const DECODER_ORDER = [dnsDecoder, httpDecoder, tlsDecoder, sshDecoder, ftpDecoder, smbDecoder, rdpDecoder, sqlDecoder];

export const detectLayer7Metadata = (packet) => {
  if (!packet.payloadBuffer || packet.payloadBuffer.length === 0) {
    return fallbackResult;
  }

  for (const decoder of DECODER_ORDER) {
    if (!decoder.matches(packet)) {
      continue;
    }

    const result = decoder.decode(packet);
    if (result) {
      return result;
    }
  }

  const fallbackHttp = httpDecoder.decode(packet);
  return fallbackHttp ?? fallbackResult;
};

```

## File: `server/decoders/rdp.js`  
- Path: `server/decoders/rdp.js`  
- Size: 817 Bytes  
- Modified: 2026-03-13 13:00:28 UTC

```javascript
import { hasPort, payloadToUtf8 } from './helpers.js';

const X224_TYPES = {
  0xe0: 'connection_request',
  0xd0: 'connection_confirm',
  0xf0: 'data',
};

export const rdpDecoder = {
  id: 'RDP',
  matches(packet) {
    return hasPort(packet, [3389]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    if (payload.length < 7 || payload[0] !== 0x03 || payload[1] !== 0x00) {
      return null;
    }

    const payloadText = payloadToUtf8(payload);
    const cookieMatch = payloadText.match(/Cookie:\s*mstshash=([^\r\n]+)/i);
    const x224Type = payload.length > 5 ? X224_TYPES[payload[5]] ?? `0x${payload[5].toString(16)}` : '';

    return {
      l7Protocol: 'RDP',
      l7Metadata: {
        rdpCookie: cookieMatch?.[1]?.trim() || '',
        rdpX224Type: x224Type,
      },
    };
  },
};

```

## File: `server/decoders/smb.js`  
- Path: `server/decoders/smb.js`  
- Size: 1277 Bytes  
- Modified: 2026-03-13 13:00:36 UTC

```javascript
import { hasPort } from './helpers.js';

const SMB2_COMMANDS = {
  0x0000: 'NEGOTIATE',
  0x0001: 'SESSION_SETUP',
  0x0003: 'TREE_CONNECT',
  0x0005: 'CREATE',
  0x0008: 'READ',
  0x0009: 'WRITE',
  0x000b: 'IOCTL',
};

const SMB1_COMMANDS = {
  0x72: 'NEGOTIATE',
  0x73: 'SESSION_SETUP',
  0x75: 'TREE_CONNECT',
  0xa2: 'NT_CREATE',
  0x25: 'TRANS',
};

export const smbDecoder = {
  id: 'SMB',
  matches(packet) {
    return hasPort(packet, [139, 445]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    if (payload.length < 8) {
      return null;
    }

    if (payload[0] === 0xfe && payload.subarray(1, 4).toString('ascii') === 'SMB') {
      const commandCode = payload.readUInt16LE(12);
      return {
        l7Protocol: 'SMB',
        l7Metadata: {
          smbDialect: 'SMB2',
          smbCommand: SMB2_COMMANDS[commandCode] ?? `0x${commandCode.toString(16)}`,
        },
      };
    }

    if (payload[0] === 0xff && payload.subarray(1, 4).toString('ascii') === 'SMB') {
      const commandCode = payload[4];
      return {
        l7Protocol: 'SMB',
        l7Metadata: {
          smbDialect: 'SMB1',
          smbCommand: SMB1_COMMANDS[commandCode] ?? `0x${commandCode.toString(16)}`,
        },
      };
    }

    return null;
  },
};

```

## File: `server/decoders/sql.js`  
- Path: `server/decoders/sql.js`  
- Size: 1739 Bytes  
- Modified: 2026-03-13 13:00:46 UTC

```javascript
import { hasPort } from './helpers.js';

const decodeUtf8 = (buffer) => {
  try {
    return buffer.toString('utf8').replace(/\0/g, ' ').trim();
  } catch {
    return '';
  }
};

const detectMySql = (payload) => {
  if (payload.length > 5 && payload[4] === 0x03) {
    return {
      engine: 'MySQL',
      operation: 'COM_QUERY',
      query: decodeUtf8(payload.subarray(5, 64)),
    };
  }
  return null;
};

const detectPostgres = (payload) => {
  if (payload.length > 6 && payload[0] === 0x51) {
    return {
      engine: 'PostgreSQL',
      operation: 'QUERY',
      query: decodeUtf8(payload.subarray(5, 64)),
    };
  }

  if (payload.length >= 8) {
    const version = payload.readUInt32BE(4);
    if (version === 0x00030000) {
      return {
        engine: 'PostgreSQL',
        operation: 'STARTUP',
        query: '',
      };
    }
  }

  return null;
};

const detectMssql = (payload) => {
  if (payload.length < 8) {
    return null;
  }

  const typeMap = {
    0x01: 'SQL_BATCH',
    0x10: 'LOGIN',
    0x12: 'PRELOGIN',
  };
  const packetType = payload[0];
  if (!typeMap[packetType]) {
    return null;
  }

  return {
    engine: 'MSSQL',
    operation: typeMap[packetType],
    query: '',
  };
};

export const sqlDecoder = {
  id: 'SQL',
  matches(packet) {
    return hasPort(packet, [1433, 3306, 5432]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    const detected = detectMySql(payload) ?? detectPostgres(payload) ?? detectMssql(payload);
    if (!detected) {
      return null;
    }

    return {
      l7Protocol: 'SQL',
      l7Metadata: {
        sqlEngine: detected.engine,
        sqlOperation: detected.operation,
        sqlQuerySnippet: detected.query,
      },
    };
  },
};

```

## File: `server/decoders/ssh.js`  
- Path: `server/decoders/ssh.js`  
- Size: 697 Bytes  
- Modified: 2026-03-13 13:00:18 UTC

```javascript
import { hasPort, payloadToUtf8 } from './helpers.js';

export const sshDecoder = {
  id: 'SSH',
  matches(packet) {
    return hasPort(packet, [22]);
  },
  decode(packet) {
    const payloadText = payloadToUtf8(packet.payloadBuffer);
    const firstLine = payloadText.split('\n')[0]?.trim() ?? '';
    if (!firstLine.startsWith('SSH-')) {
      return null;
    }

    const bannerParts = firstLine.split('-');
    const versionPart = bannerParts[1] ?? '';
    const softwarePart = bannerParts.slice(2).join('-');

    return {
      l7Protocol: 'SSH',
      l7Metadata: {
        sshBanner: firstLine,
        sshVersion: versionPart,
        sshSoftware: softwarePart,
      },
    };
  },
};

```

## File: `server/decoders/tls.js`  
- Path: `server/decoders/tls.js`  
- Size: 2435 Bytes  
- Modified: 2026-03-13 13:00:14 UTC

```javascript
import { hasPort } from './helpers.js';

const TLS_VERSIONS = {
  0x0301: 'TLS1.0',
  0x0302: 'TLS1.1',
  0x0303: 'TLS1.2',
  0x0304: 'TLS1.3',
};

export const tlsDecoder = {
  id: 'TLS',
  matches(packet) {
    return hasPort(packet, [443, 8443]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    if (payload.length < 43 || payload[0] !== 0x16) {
      return null;
    }

    const recordLength = payload.readUInt16BE(3);
    const version = payload.readUInt16BE(1);
    if (payload.length < 5 + recordLength || payload[5] !== 0x01) {
      return null;
    }

    let cursor = 9;
    cursor += 2;
    cursor += 32;
    if (cursor >= payload.length) {
      return null;
    }

    const sessionIdLength = payload[cursor];
    cursor += 1 + sessionIdLength;
    if (cursor + 2 > payload.length) {
      return null;
    }

    const cipherSuiteLength = payload.readUInt16BE(cursor);
    cursor += 2 + cipherSuiteLength;
    if (cursor >= payload.length) {
      return null;
    }

    const compressionLength = payload[cursor];
    cursor += 1 + compressionLength;
    if (cursor + 2 > payload.length) {
      return null;
    }

    const extensionsLength = payload.readUInt16BE(cursor);
    cursor += 2;
    const extensionsEnd = cursor + extensionsLength;
    let sni = '';

    while (cursor + 4 <= extensionsEnd && cursor + 4 <= payload.length) {
      const extensionType = payload.readUInt16BE(cursor);
      const extensionLength = payload.readUInt16BE(cursor + 2);
      cursor += 4;

      if (extensionType === 0x0000 && cursor + 2 <= payload.length) {
        const serverNameListLength = payload.readUInt16BE(cursor);
        let serverCursor = cursor + 2;
        const serverNameListEnd = serverCursor + serverNameListLength;

        while (serverCursor + 3 <= serverNameListEnd && serverCursor + 3 <= payload.length) {
          const nameType = payload[serverCursor];
          const nameLength = payload.readUInt16BE(serverCursor + 1);
          serverCursor += 3;
          if (nameType === 0x00) {
            sni = payload.subarray(serverCursor, serverCursor + nameLength).toString('utf8');
            break;
          }
          serverCursor += nameLength;
        }
      }

      cursor += extensionLength;
    }

    return {
      l7Protocol: 'TLS',
      l7Metadata: {
        sni,
        tlsVersion: TLS_VERSIONS[version] ?? `0x${version.toString(16)}`,
      },
    };
  },
};

```

## File: `server/defaultConfig.js`  
- Path: `server/defaultConfig.js`  
- Size: 4084 Bytes  
- Modified: 2026-03-13 13:42:00 UTC

```javascript
import crypto from 'node:crypto';

export const PROVIDER_DEFINITIONS = [
  {
    id: 'gemini',
    label: 'Gemini',
    transport: 'gemini',
    defaultModel: 'gemini-2.5-flash',
    defaultBaseUrl: 'https://generativelanguage.googleapis.com',
    envVar: 'GEMINI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'openai',
    label: 'OpenAI',
    transport: 'openai-compatible',
    defaultModel: 'gpt-4.1-mini',
    defaultBaseUrl: 'https://api.openai.com/v1',
    envVar: 'OPENAI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'anthropic',
    label: 'Anthropic',
    transport: 'anthropic',
    defaultModel: 'claude-3-5-sonnet-latest',
    defaultBaseUrl: 'https://api.anthropic.com',
    envVar: 'ANTHROPIC_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'openrouter',
    label: 'OpenRouter',
    transport: 'openai-compatible',
    defaultModel: 'openai/gpt-4.1-mini',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    envVar: 'OPENROUTER_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'groq',
    label: 'Groq',
    transport: 'openai-compatible',
    defaultModel: 'llama-3.3-70b-versatile',
    defaultBaseUrl: 'https://api.groq.com/openai/v1',
    envVar: 'GROQ_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'mistral',
    label: 'Mistral',
    transport: 'openai-compatible',
    defaultModel: 'mistral-small-latest',
    defaultBaseUrl: 'https://api.mistral.ai/v1',
    envVar: 'MISTRAL_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    transport: 'openai-compatible',
    defaultModel: 'deepseek-chat',
    defaultBaseUrl: 'https://api.deepseek.com',
    envVar: 'DEEPSEEK_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'xai',
    label: 'xAI',
    transport: 'openai-compatible',
    defaultModel: 'grok-2-latest',
    defaultBaseUrl: 'https://api.x.ai/v1',
    envVar: 'XAI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'lmstudio',
    label: 'LM Studio',
    transport: 'openai-compatible',
    defaultModel: 'local-model',
    defaultBaseUrl: 'http://localhost:1234/v1',
    envVar: '',
    requiresApiKey: false,
    local: true,
  },
  {
    id: 'ollama',
    label: 'Ollama',
    transport: 'ollama',
    defaultModel: 'llama3.2',
    defaultBaseUrl: 'http://localhost:11434',
    envVar: '',
    requiresApiKey: false,
    local: true,
  },
];

export const createDefaultProviderSettings = () =>
  Object.fromEntries(
    PROVIDER_DEFINITIONS.map(definition => [
      definition.id,
      {
        model: definition.defaultModel,
        baseUrl: definition.defaultBaseUrl,
        apiKey: '',
      },
    ])
  );

const createThreatIntelSources = () => ([
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
]);

export const createDefaultServerConfig = () => ({
  llmProvider: 'lmstudio',
  providerSettings: createDefaultProviderSettings(),
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
  threatIntelSources: createThreatIntelSources(),
  blockedIps: [],
  blockedPorts: [],
  exemptPorts: [],
  webhookIntegrations: [],
  customRules: [],
});

```

## File: `server/firewallManager.js`  
- Path: `server/firewallManager.js`  
- Size: 3019 Bytes  
- Modified: 2026-03-13 12:04:54 UTC

```javascript
import os from 'node:os';
import net from 'node:net';
import { spawn } from 'node:child_process';

const executeCommand = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
    });

    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(stderr || stdout || `Command exited with code ${code}`));
      }
    });
  });

const commandExists = async (command) => {
  const checker = os.platform() === 'win32' ? 'where' : 'which';
  try {
    await executeCommand(checker, [command]);
    return true;
  } catch {
    return false;
  }
};

export class FirewallManager {
  constructor() {
    this.blockedIps = new Set();
    this.platform = os.platform();
    this.linuxProviderPromise = null;
  }

  async getLinuxProvider() {
    if (this.linuxProviderPromise) {
      return this.linuxProviderPromise;
    }

    this.linuxProviderPromise = (async () => {
      if (await commandExists('ufw')) {
        return 'ufw';
      }
      if (await commandExists('iptables')) {
        return 'iptables';
      }
      throw new Error('No supported Linux firewall command found. Install ufw or iptables.');
    })();

    return this.linuxProviderPromise;
  }

  validateIpAddress(ipAddress) {
    if (net.isIP(ipAddress) === 0) {
      throw new Error(`Invalid IP address: ${ipAddress}`);
    }
  }

  async blockIp(ipAddress) {
    this.validateIpAddress(ipAddress);

    if (this.blockedIps.has(ipAddress)) {
      return {
        applied: false,
        provider: this.platform,
        message: 'IP address is already blocked by NetGuard.',
      };
    }

    if (this.platform === 'win32') {
      await executeCommand('netsh', [
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=NetGuard Block ${ipAddress}`,
        'dir=in',
        'action=block',
        `remoteip=${ipAddress}`,
      ]);
      this.blockedIps.add(ipAddress);
      return {
        applied: true,
        provider: 'netsh',
        message: `Windows firewall rule created for ${ipAddress}.`,
      };
    }

    if (this.platform === 'linux') {
      const provider = await this.getLinuxProvider();
      if (provider === 'ufw') {
        await executeCommand('ufw', ['deny', 'from', ipAddress]);
      } else {
        await executeCommand('iptables', ['-A', 'INPUT', '-s', ipAddress, '-j', 'DROP']);
      }

      this.blockedIps.add(ipAddress);
      return {
        applied: true,
        provider,
        message: `Linux firewall rule created for ${ipAddress}.`,
      };
    }

    throw new Error(`Firewall integration is not supported on platform: ${this.platform}`);
  }
}

```

## File: `server/fleetService.js`  
- Path: `server/fleetService.js`  
- Size: 12379 Bytes  
- Modified: 2026-03-13 13:43:38 UTC

```javascript
import { WebSocket } from 'ws';

const createFleetStatus = (config = {}) => ({
  deploymentMode: config.deploymentMode ?? 'standalone',
  sensorId: config.sensorId ?? 'desktop-lab-01',
  sensorName: config.sensorName ?? 'Windows Lab Sensor',
  connectedToHub: false,
  connectedSensors: 0,
  hubUrl: config.hubUrl || null,
  lastSyncAt: null,
  lastError: null,
});

const buildHubSocketUrl = (hubUrl, config) => {
  const parsed = new URL(hubUrl.trim());
  parsed.protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
  parsed.pathname = '/fleet/agent';
  parsed.searchParams.set('sensorId', config.sensorId);
  parsed.searchParams.set('sensorName', config.sensorName);
  parsed.searchParams.set('token', config.fleetSharedToken || '');
  return parsed.toString();
};

export class FleetService {
  constructor({ getConfiguration, onSensorUpdate, onFleetStatus, onRemoteTraffic, onRemoteLog, onRemoteArtifact, onGlobalBlock }) {
    this.getConfiguration = getConfiguration;
    this.onSensorUpdate = onSensorUpdate;
    this.onFleetStatus = onFleetStatus;
    this.onRemoteTraffic = onRemoteTraffic;
    this.onRemoteLog = onRemoteLog;
    this.onRemoteArtifact = onRemoteArtifact;
    this.onGlobalBlock = onGlobalBlock;
    this.connectedAgents = new Map();
    this.hubSocket = null;
    this.reconnectTimer = null;
    this.localCaptureStatus = null;
    this.localMetrics = null;
    this.fleetStatus = createFleetStatus(this.getConfiguration());
    this.publishFleetStatus();
  }

  stop() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.hubSocket) {
      this.hubSocket.removeAllListeners?.();
      this.hubSocket.close();
      this.hubSocket = null;
    }

    for (const agent of this.connectedAgents.values()) {
      agent.socket.close();
    }
    this.connectedAgents.clear();
  }

  configure(config) {
    this.fleetStatus = {
      ...this.fleetStatus,
      deploymentMode: config.deploymentMode,
      sensorId: config.sensorId,
      sensorName: config.sensorName,
      hubUrl: config.hubUrl || null,
      lastError: null,
    };

    this.publishSensorSummary();
    this.publishFleetStatus();

    if (config.deploymentMode === 'agent' && config.hubUrl) {
      this.ensureAgentConnection();
      return;
    }

    if (this.hubSocket) {
      this.hubSocket.close();
      this.hubSocket = null;
    }
    this.fleetStatus.connectedToHub = false;
    this.publishFleetStatus();
  }

  getStatus() {
    return {
      ...this.fleetStatus,
      connectedSensors: this.connectedAgents.size,
    };
  }

  publishFleetStatus() {
    this.onFleetStatus(this.getStatus());
  }

  buildLocalSensorSummary() {
    const config = this.getConfiguration();
    return {
      id: config.sensorId,
      name: config.sensorName,
      mode: config.deploymentMode,
      connected: config.deploymentMode === 'agent' ? this.fleetStatus.connectedToHub : true,
      hubUrl: config.hubUrl || null,
      lastSeenAt: new Date().toISOString(),
      captureRunning: Boolean(this.localCaptureStatus?.running),
      packetsProcessed: this.localMetrics?.packetsProcessed ?? 0,
      threatsDetected: this.localMetrics?.threatsDetected ?? 0,
      blockedDecisions: this.localMetrics?.blockedDecisions ?? 0,
      lastEventAt: this.localMetrics?.lastUpdatedAt ?? this.localCaptureStatus?.startedAt ?? null,
      local: true,
    };
  }

  publishSensorSummary(summary = this.buildLocalSensorSummary()) {
    this.onSensorUpdate(summary);
  }

  publishCaptureStatus(status) {
    this.localCaptureStatus = status;
    this.publishSensorSummary();
    this.sendToHub({
      type: 'status',
      payload: status,
    });
  }

  publishMetrics(metrics) {
    this.localMetrics = metrics;
    this.publishSensorSummary();
    this.sendToHub({
      type: 'metrics',
      payload: metrics,
    });
  }

  publishTraffic(entry) {
    this.sendToHub({
      type: 'traffic',
      payload: entry,
    });
  }

  publishLog(entry) {
    this.sendToHub({
      type: 'log',
      payload: entry,
    });
  }

  publishArtifact(artifact) {
    this.sendToHub({
      type: 'artifact',
      payload: artifact,
    });
  }

  propagateGlobalBlock(ipAddress, details = {}) {
    const config = this.getConfiguration();
    if (!config.globalBlockPropagationEnabled) {
      return;
    }

    if (config.deploymentMode === 'hub') {
      this.broadcastToAgents({
        type: 'global-block',
        payload: {
          ipAddress,
          reason: details.reason || 'Threat detected on peer sensor.',
        },
      });
      this.fleetStatus.lastSyncAt = new Date().toISOString();
      this.publishFleetStatus();
      return;
    }

    if (config.deploymentMode === 'agent') {
      this.sendToHub({
        type: 'global-block-proposal',
        payload: {
          ipAddress,
          reason: details.reason || 'Threat detected on agent sensor.',
        },
      });
    }
  }

  ensureAgentConnection() {
    const config = this.getConfiguration();
    if (config.deploymentMode !== 'agent' || !config.hubUrl || this.hubSocket || this.reconnectTimer) {
      return;
    }

    let socketUrl;
    try {
      socketUrl = buildHubSocketUrl(config.hubUrl, config);
    } catch (error) {
      this.fleetStatus.lastError = error instanceof Error ? error.message : 'Invalid hub URL.';
      this.publishFleetStatus();
      return;
    }

    const socket = new WebSocket(socketUrl);
    this.hubSocket = socket;

    socket.on('open', () => {
      this.fleetStatus.connectedToHub = true;
      this.fleetStatus.lastError = null;
      this.fleetStatus.lastSyncAt = new Date().toISOString();
      this.publishFleetStatus();
      this.sendToHub({ type: 'hello', payload: this.buildLocalSensorSummary() });
      if (this.localCaptureStatus) {
        this.sendToHub({ type: 'status', payload: this.localCaptureStatus });
      }
      if (this.localMetrics) {
        this.sendToHub({ type: 'metrics', payload: this.localMetrics });
      }
    });

    socket.on('message', data => {
      try {
        const message = JSON.parse(data.toString());
        if (message?.type === 'global-block' && message?.payload?.ipAddress) {
          this.onGlobalBlock(message.payload.ipAddress, {
            reason: message.payload.reason || 'Fleet global block propagated by hub.',
          });
          this.fleetStatus.lastSyncAt = new Date().toISOString();
          this.publishFleetStatus();
        }
      } catch (error) {
        this.fleetStatus.lastError = error instanceof Error ? error.message : 'Failed to decode fleet message.';
        this.publishFleetStatus();
      }
    });

    const handleDisconnect = () => {
      if (this.hubSocket === socket) {
        this.hubSocket = null;
      }
      this.fleetStatus.connectedToHub = false;
      this.publishFleetStatus();

      if (this.getConfiguration().deploymentMode === 'agent' && !this.reconnectTimer) {
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.ensureAgentConnection();
        }, 3000);
      }
    };

    socket.on('close', handleDisconnect);
    socket.on('error', error => {
      this.fleetStatus.lastError = error instanceof Error ? error.message : 'Fleet socket error.';
      this.publishFleetStatus();
    });
  }

  sendToHub(message) {
    if (!this.hubSocket || this.hubSocket.readyState !== WebSocket.OPEN) {
      return;
    }
    this.hubSocket.send(JSON.stringify(message));
  }

  broadcastToAgents(message, exceptSensorId = null) {
    const payload = JSON.stringify(message);
    for (const [sensorId, agent] of this.connectedAgents.entries()) {
      if (sensorId === exceptSensorId) {
        continue;
      }
      if (agent.socket.readyState === WebSocket.OPEN) {
        agent.socket.send(payload);
      }
    }
  }

  handleHubConnection(socket, request) {
    const config = this.getConfiguration();
    if (config.deploymentMode !== 'hub') {
      socket.close(1008, 'Fleet hub mode is disabled.');
      return;
    }

    const requestUrl = new URL(request.url, 'http://localhost');
    const sensorId = requestUrl.searchParams.get('sensorId') || '';
    const sensorName = requestUrl.searchParams.get('sensorName') || sensorId || 'Remote Sensor';
    const token = requestUrl.searchParams.get('token') || '';

    if (!sensorId) {
      socket.close(1008, 'Missing sensor identifier.');
      return;
    }

    if (config.fleetSharedToken && token !== config.fleetSharedToken) {
      socket.close(1008, 'Invalid fleet token.');
      return;
    }

    const initialSummary = {
      id: sensorId,
      name: sensorName,
      mode: 'agent',
      connected: true,
      hubUrl: null,
      lastSeenAt: new Date().toISOString(),
      captureRunning: false,
      packetsProcessed: 0,
      threatsDetected: 0,
      blockedDecisions: 0,
      lastEventAt: null,
      local: false,
    };

    this.connectedAgents.set(sensorId, {
      socket,
      summary: initialSummary,
    });
    this.onSensorUpdate(initialSummary);
    this.publishFleetStatus();

    socket.on('message', data => {
      try {
        const message = JSON.parse(data.toString());
        const agent = this.connectedAgents.get(sensorId);
        if (!agent) {
          return;
        }

        agent.summary = {
          ...agent.summary,
          lastSeenAt: new Date().toISOString(),
        };

        switch (message?.type) {
          case 'hello':
            if (message.payload?.name) {
              agent.summary.name = message.payload.name;
            }
            break;
          case 'status':
            agent.summary.captureRunning = Boolean(message.payload?.running);
            break;
          case 'metrics':
            agent.summary.packetsProcessed = Number(message.payload?.packetsProcessed ?? agent.summary.packetsProcessed);
            agent.summary.threatsDetected = Number(message.payload?.threatsDetected ?? agent.summary.threatsDetected);
            agent.summary.blockedDecisions = Number(message.payload?.blockedDecisions ?? agent.summary.blockedDecisions);
            agent.summary.lastEventAt = message.payload?.lastUpdatedAt ?? agent.summary.lastEventAt;
            break;
          case 'traffic':
            agent.summary.lastEventAt = message.payload?.createdAt ?? new Date().toISOString();
            this.onRemoteTraffic(message.payload, agent.summary);
            break;
          case 'log':
            agent.summary.lastEventAt = message.payload?.timestamp ?? new Date().toISOString();
            this.onRemoteLog(message.payload, agent.summary);
            break;
          case 'artifact':
            agent.summary.lastEventAt = message.payload?.createdAt ?? new Date().toISOString();
            this.onRemoteArtifact(message.payload, agent.summary);
            break;
          case 'global-block-proposal':
            if (message.payload?.ipAddress && config.globalBlockPropagationEnabled) {
              this.onGlobalBlock(message.payload.ipAddress, {
                reason: message.payload.reason || `Hub propagated block from ${agent.summary.name}.`,
              });
              this.broadcastToAgents({
                type: 'global-block',
                payload: {
                  ipAddress: message.payload.ipAddress,
                  reason: message.payload.reason || `Hub propagated block from ${agent.summary.name}.`,
                },
              }, sensorId);
              this.fleetStatus.lastSyncAt = new Date().toISOString();
              this.publishFleetStatus();
            }
            break;
          default:
            break;
        }

        this.onSensorUpdate(agent.summary);
      } catch (error) {
        socket.send(JSON.stringify({
          type: 'error',
          payload: {
            message: error instanceof Error ? error.message : 'Failed to process fleet message.',
          },
        }));
      }
    });

    socket.on('close', () => {
      const agent = this.connectedAgents.get(sensorId);
      if (agent) {
        agent.summary = {
          ...agent.summary,
          connected: false,
          lastSeenAt: new Date().toISOString(),
        };
        this.onSensorUpdate(agent.summary);
      }
      this.connectedAgents.delete(sensorId);
      this.publishFleetStatus();
    });
  }
}

```

## File: `server/forensicsChatService.js`  
- Path: `server/forensicsChatService.js`  
- Size: 3297 Bytes  
- Modified: 2026-03-13 13:02:44 UTC

```javascript
import crypto from 'node:crypto';
import { executeReadOnlyQuery, getForensicsSchema, insertForensicsQuery } from './db.js';
import { requestProviderJson, Type } from './llmService.js';

const SQL_PLAN_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    sql: { type: Type.STRING },
    reasoning: { type: Type.STRING },
  },
  required: ['sql', 'reasoning'],
};

const SUMMARY_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    summary: { type: Type.STRING },
  },
  required: ['summary'],
};

const SQL_SYSTEM_PROMPT = `You translate security forensics questions into read-only SQLite SQL.
Return strictly valid JSON and nothing else.
Rules:
- Only produce SELECT statements or CTEs that end in a SELECT.
- Never use INSERT, UPDATE, DELETE, DROP, ALTER, ATTACH, DETACH, PRAGMA, VACUUM, or transaction commands.
- Prefer explicit column lists.
- Use SQLite syntax.
- Limit the final result to 200 rows or fewer.`;

const SUMMARY_SYSTEM_PROMPT = `You summarize security forensics query results.
Return strictly valid JSON and nothing else.
Keep the summary concise and analyst-focused.`;

const isSafeReadOnlySql = (sql) => {
  const normalized = sql.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (!(normalized.startsWith('select') || normalized.startsWith('with'))) {
    return false;
  }

  if (normalized.includes(';')) {
    return false;
  }

  return !/\b(insert|update|delete|drop|alter|attach|detach|pragma|vacuum|begin|commit|rollback|replace|create)\b/i.test(sql);
};

const ensureLimit = (sql) => {
  if (/\blimit\s+\d+\b/i.test(sql)) {
    return sql;
  }

  return `SELECT * FROM (${sql}) AS threat_hunt_results LIMIT 200`;
};

export class ForensicsChatService {
  async runQuestion({ question, sensorId, config }) {
    const schema = getForensicsSchema();
    const sensorInstruction = sensorId
      ? `The user is currently scoped to sensor_id = "${sensorId}". Prefer filtering to that sensor unless the user clearly asks for global data.`
      : 'The user is asking for a global view across all sensors unless they request otherwise.';

    const planningPrompt = `Schema:\n${JSON.stringify(schema, null, 2)}\n\n${sensorInstruction}\n\nQuestion:\n${question}`;
    const plannedQuery = await requestProviderJson(config, planningPrompt, SQL_PLAN_SCHEMA, {
      systemPrompt: SQL_SYSTEM_PROMPT,
    });

    const sql = typeof plannedQuery?.sql === 'string' ? plannedQuery.sql.trim() : '';
    if (!isSafeReadOnlySql(sql)) {
      throw new Error('The generated SQL query was rejected by the read-only safety policy.');
    }

    const limitedSql = ensureLimit(sql);
    const rows = executeReadOnlyQuery(limitedSql);

    const summaryPrompt = `Question:\n${question}\n\nSQL:\n${limitedSql}\n\nRows:\n${JSON.stringify(rows, null, 2)}`;
    const summaryResponse = await requestProviderJson(config, summaryPrompt, SUMMARY_SCHEMA, {
      systemPrompt: SUMMARY_SYSTEM_PROMPT,
    });

    const result = {
      id: crypto.randomUUID(),
      question,
      sql: limitedSql,
      summary: typeof summaryResponse?.summary === 'string' ? summaryResponse.summary.trim() : 'No summary returned.',
      rows,
      generatedAt: new Date().toISOString(),
      sensorId: sensorId ?? null,
    };

    insertForensicsQuery(result);
    return result;
  }
}

```

## File: `server/heuristicAnalyzer.js`  
- Path: `server/heuristicAnalyzer.js`  
- Size: 10408 Bytes  
- Modified: 2026-03-13 14:00:44 UTC

```javascript
import net from 'node:net';

const DDOS_WINDOW_MS = 5_000;
const DDOS_PACKET_THRESHOLD = 150;
const PORT_SCAN_WINDOW_MS = 15_000;
const PORT_SCAN_PORT_THRESHOLD = 12;
const BRUTE_FORCE_WINDOW_MS = 30_000;
const BRUTE_FORCE_ATTEMPTS = 16;

const SENSITIVE_PORTS = new Set([21, 22, 23, 25, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432]);
const BRUTE_FORCE_PORTS = new Set([21, 22, 23, 25, 110, 143, 587, 993, 995, 1433, 1521, 3306, 3389, 5432]);
const BRUTE_FORCE_L7_PROTOCOLS = new Set(['SSH', 'FTP', 'RDP', 'SQL']);
const COMMON_BENIGN_PORTS = new Set([53, 80, 123, 443, 853]);
const MALICIOUS_KEYWORDS = [
  'powershell',
  'invoke-expression',
  'cmd.exe',
  '/bin/sh',
  'wget ',
  'curl ',
  'nc -e',
  'mimikatz',
  'union select',
  'drop table',
  '../',
  '<?php',
];

const decodeHexSnippet = (hexValue) => {
  try {
    const bytes = new Uint8Array(
      hexValue.match(/.{1,2}/g)?.map(byte => Number.parseInt(byte, 16)).filter(byte => !Number.isNaN(byte)) ?? []
    );
    return new TextDecoder().decode(bytes).toLowerCase();
  } catch {
    return '';
  }
};

const prune = (timestamps, cutoff) => timestamps.filter(timestamp => timestamp >= cutoff);

const pruneAttemptsByTarget = (attemptsByTarget, cutoff) => {
  for (const [targetKey, timestamps] of attemptsByTarget.entries()) {
    const prunedTimestamps = prune(timestamps, cutoff);
    if (prunedTimestamps.length === 0) {
      attemptsByTarget.delete(targetKey);
      continue;
    }
    attemptsByTarget.set(targetKey, prunedTimestamps);
  }
};

const buildResult = (packet, overrides = {}) => ({
  isSuspicious: false,
  attackType: 'none',
  confidence: 0.05,
  explanation: 'No heuristic anomaly detected.',
  packet,
  decisionSource: 'heuristic',
  matchedSignals: [],
  ...overrides,
});

const getPacketFieldValue = (packet, field) => {
  switch (field) {
    case 'sourceIp':
      return packet.sourceIp;
    case 'destinationIp':
      return packet.destinationIp;
    case 'sourcePort':
      return packet.sourcePort;
    case 'destinationPort':
      return packet.destinationPort;
    case 'protocol':
      return packet.protocol;
    case 'direction':
      return packet.direction;
    case 'size':
      return packet.size;
    case 'l7Protocol':
      return packet.l7Protocol;
    case 'payloadSnippet':
      return packet.payloadSnippet;
    default:
      if (field.startsWith('l7.')) {
        return packet.l7Metadata[field.slice(3)] ?? '';
      }
      return '';
  }
};

const matchesCidr = (ipAddress, cidrNotation) => {
  const [networkAddress, prefixLengthText] = cidrNotation.split('/');
  const prefixLength = Number(prefixLengthText);
  const family = net.isIP(networkAddress);
  if (!family || !net.isIP(ipAddress) || !Number.isInteger(prefixLength)) {
    return false;
  }

  const blockList = new net.BlockList();
  blockList.addSubnet(networkAddress, prefixLength, family === 6 ? 'ipv6' : 'ipv4');
  return blockList.check(ipAddress, family === 6 ? 'ipv6' : 'ipv4');
};

const evaluateCondition = (packet, condition) => {
  const fieldValue = getPacketFieldValue(packet, condition.field);
  const normalizedValue = String(fieldValue);
  const numericFieldValue = Number(fieldValue);
  const numericConditionValue = Number(condition.value);
  const listValues = condition.value.split(',').map(item => item.trim()).filter(Boolean);

  switch (condition.operator) {
    case 'equals':
      return normalizedValue === condition.value;
    case 'not_equals':
      return normalizedValue !== condition.value;
    case 'greater_than':
      return Number.isFinite(numericFieldValue) && Number.isFinite(numericConditionValue) && numericFieldValue > numericConditionValue;
    case 'less_than':
      return Number.isFinite(numericFieldValue) && Number.isFinite(numericConditionValue) && numericFieldValue < numericConditionValue;
    case 'contains':
      return normalizedValue.toLowerCase().includes(condition.value.toLowerCase());
    case 'starts_with':
      return normalizedValue.toLowerCase().startsWith(condition.value.toLowerCase());
    case 'in_cidr':
      return matchesCidr(normalizedValue, condition.value);
    case 'not_in_cidr':
      return !matchesCidr(normalizedValue, condition.value);
    case 'in_list':
      return listValues.includes(normalizedValue);
    case 'not_in_list':
      return !listValues.includes(normalizedValue);
    default:
      return false;
  }
};

export class HeuristicAnalyzer {
  constructor() {
    this.sourceState = new Map();
  }

  reset() {
    this.sourceState.clear();
  }

  getSourceState(sourceIp) {
    const existing = this.sourceState.get(sourceIp);
    if (existing) {
      return existing;
    }

    const nextState = {
      packetTimestamps: [],
      authAttemptsByTarget: new Map(),
      portTouches: [],
    };
    this.sourceState.set(sourceIp, nextState);
    return nextState;
  }

  evaluate(packet, config) {
    for (const rule of config.customRules) {
      if (!rule.enabled) {
        continue;
      }

      const conditionResults = rule.conditions.map(condition => evaluateCondition(packet, condition));
      const matched = rule.matchMode === 'all' ? conditionResults.every(Boolean) : conditionResults.some(Boolean);

      if (matched) {
        return {
          result: buildResult(packet, {
            isSuspicious: rule.outcome.attackType !== 'none' && rule.outcome.actionType !== 'ALLOW',
            attackType: rule.outcome.attackType,
            confidence: rule.outcome.confidence,
            explanation: rule.outcome.explanation,
            decisionSource: 'custom_rule',
            matchedSignals: [`custom_rule:${rule.name}`],
            recommendedActionType: rule.outcome.actionType,
            recommendedTargetPort: rule.outcome.targetPort,
          }),
          needsDeepInspection: rule.outcome.needsDeepInspection,
        };
      }
    }

    const now = Date.parse(packet.timestamp) || Date.now();
    const state = this.getSourceState(packet.sourceIp);
    const payloadText = decodeHexSnippet(packet.payloadSnippet);
    const bruteForceCandidate = packet.protocol === 'TCP'
      && packet.direction === 'INBOUND'
      && (
        BRUTE_FORCE_PORTS.has(packet.destinationPort)
        || BRUTE_FORCE_L7_PROTOCOLS.has(packet.l7Protocol)
      );
    const bruteForceTargetKey = bruteForceCandidate
      ? `${packet.destinationIp}:${packet.destinationPort}:${packet.l7Protocol}`
      : null;

    state.packetTimestamps.push(now);
    pruneAttemptsByTarget(state.authAttemptsByTarget, now - BRUTE_FORCE_WINDOW_MS);
    state.portTouches = state.portTouches.filter(entry => entry.timestamp >= now - PORT_SCAN_WINDOW_MS);
    state.packetTimestamps = prune(state.packetTimestamps, now - DDOS_WINDOW_MS);
    state.portTouches.push({ port: packet.destinationPort, timestamp: now });

    if (bruteForceTargetKey) {
      const attempts = state.authAttemptsByTarget.get(bruteForceTargetKey) ?? [];
      attempts.push(now);
      state.authAttemptsByTarget.set(bruteForceTargetKey, attempts);
    }

    const uniqueTouchedPorts = new Set(state.portTouches.map(entry => entry.port));
    const targetAttempts = bruteForceTargetKey ? state.authAttemptsByTarget.get(bruteForceTargetKey) ?? [] : [];

    if (state.packetTimestamps.length >= DDOS_PACKET_THRESHOLD) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'ddos',
          confidence: 0.99,
          explanation: 'High packet rate from the same source indicates a volumetric attack.',
          matchedSignals: ['rate.ddos.threshold'],
          recommendedActionType: 'BLOCK',
        }),
        needsDeepInspection: false,
      };
    }

    if (uniqueTouchedPorts.size >= PORT_SCAN_PORT_THRESHOLD) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'port_scan',
          confidence: 0.96,
          explanation: 'The same source probed many destination ports in a short time window.',
          matchedSignals: ['behavior.port_scan.multiple_ports'],
          recommendedActionType: 'BLOCK',
        }),
        needsDeepInspection: false,
      };
    }

    if (bruteForceTargetKey && targetAttempts.length >= BRUTE_FORCE_ATTEMPTS) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'brute_force',
          confidence: 0.94,
          explanation: 'Repeated inbound authentication attempts against the same service suggest a brute-force attack.',
          matchedSignals: ['behavior.brute_force.same_target_repeated_auth'],
          recommendedActionType: 'BLOCK',
        }),
        needsDeepInspection: false,
      };
    }

    if (payloadText && MALICIOUS_KEYWORDS.some(keyword => payloadText.includes(keyword))) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'malicious_payload',
          confidence: 0.97,
          explanation: 'Known malicious command patterns were found in the packet payload.',
          matchedSignals: ['payload.signature.known_malicious'],
          recommendedActionType: 'REDIRECT',
          recommendedTargetPort: config.securePort,
        }),
        needsDeepInspection: false,
      };
    }

    if (packet.l7Protocol === 'SSH' && packet.l7Metadata.sshBanner && packet.direction === 'INBOUND') {
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    if (packet.l7Protocol === 'SMB' && packet.direction === 'INBOUND') {
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    const targetsSensitivePort = SENSITIVE_PORTS.has(packet.destinationPort) || config.monitoringPorts.includes(packet.destinationPort);
    const carriesInspectableMetadata = packet.l7Protocol !== 'UNKNOWN' || packet.payloadSnippet.length > 0;
    const isCommonBenignPort = COMMON_BENIGN_PORTS.has(packet.destinationPort);

    if ((targetsSensitivePort && packet.direction === 'INBOUND') || (carriesInspectableMetadata && !isCommonBenignPort)) {
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    return {
      result: buildResult(packet, {
        confidence: 0.08,
        explanation: 'Traffic matched benign heuristic rules and did not require deep inspection.',
      }),
      needsDeepInspection: false,
    };
  }
}

```

## File: `server/index.js`  
- Path: `server/index.js`  
- Size: 10582 Bytes  
- Modified: 2026-03-13 14:21:22 UTC

```javascript
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import multer from 'multer';
import { WebSocket, WebSocketServer } from 'ws';
import { z } from 'zod';
import {
  directories,
  getPcapArtifactById,
  listPcapArtifacts,
  listRecentLogs,
  listRecentTrafficEvents,
  listSensors,
  listTrafficMetrics,
  getTrafficCounters,
} from './db.js';
import { MonitoringService } from './monitoringService.js';
import { revealLocalPath } from './localPathService.js';

const PORT = Number(process.env.NETGUARD_SERVER_PORT || 8081);
const app = express();
const server = http.createServer(app);
const wsClients = new Set();

const upload = multer({
  dest: directories.replayDirectory,
  limits: {
    fileSize: 100 * 1024 * 1024,
  },
});

const startCaptureSchema = z.object({
  deviceName: z.string().trim().optional().default(''),
  filter: z.string().trim().min(1),
});

const replaySchema = z.object({
  speedMultiplier: z.coerce.number().positive().max(100).optional().default(10),
});

const forensicsSchema = z.object({
  question: z.string().trim().min(5),
  sensorId: z.string().trim().optional().nullable(),
});
const openLocalPathSchema = z.object({
  path: z.string().trim().min(1),
});

app.use(express.json({ limit: '2mb' }));
app.use((request, response, next) => {
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  response.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  if (request.method === 'OPTIONS') {
    response.sendStatus(204);
    return;
  }
  next();
});

app.get('/', (_, response) => {
  response.json({
    ok: true,
    service: 'NetGuard AI backend',
    message: 'This backend exposes API endpoints, a UI WebSocket stream and an agent fleet WebSocket endpoint.',
  });
});

const broadcast = message => {
  const payload = JSON.stringify(message);
  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
};

const monitoringService = new MonitoringService({ broadcast });

const getClientCount = () => wsClients.size;

app.get('/api/health', (_, response) => {
  response.json({
    ok: true,
    serverTime: new Date().toISOString(),
    capture: monitoringService.decorateCaptureStatus(monitoringService.captureAgent.getStatus(getClientCount())),
    fleet: monitoringService.getFleetStatus(),
    threatIntel: monitoringService.threatIntelStatus,
  });
});

app.get('/api/bootstrap', (request, response) => {
  const sensorId = typeof request.query.sensorId === 'string' && request.query.sensorId.trim() ? request.query.sensorId.trim() : null;
  response.json(monitoringService.getBootstrapPayload(getClientCount(), sensorId));
});

app.get('/api/interfaces', (_, response) => {
  response.json({
    interfaces: monitoringService.captureAgent.listInterfaces(),
  });
});

app.get('/api/config', (_, response) => {
  response.json({
    config: monitoringService.getClientConfiguration(),
  });
});

app.put('/api/config', (request, response) => {
  try {
    const config = monitoringService.updateConfiguration(request.body);
    response.json({
      ok: true,
      config,
    });
  } catch (error) {
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Failed to update configuration.',
    });
  }
});

app.get('/api/capture/status', (_, response) => {
  response.json(monitoringService.decorateCaptureStatus(monitoringService.captureAgent.getStatus(getClientCount())));
});

app.post('/api/capture/start', async (request, response) => {
  try {
    const payload = startCaptureSchema.parse(request.body);
    const status = await monitoringService.startCapture(payload, getClientCount());
    response.json({
      ok: true,
      status,
    });
  } catch (error) {
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Failed to start capture.',
    });
  }
});

app.post('/api/capture/stop', (_, response) => {
  const status = monitoringService.stopCapture(getClientCount());
  response.json({
    ok: true,
    status,
  });
});

app.post('/api/capture/replay', upload.single('pcap'), async (request, response) => {
  try {
    if (!request.file) {
      throw new Error('No PCAP file was uploaded.');
    }

    const payload = replaySchema.parse(request.body);
    const targetFilePath = path.join(directories.replayDirectory, `${Date.now()}_${request.file.originalname}`);
    fs.renameSync(request.file.path, targetFilePath);

    void monitoringService.replayCapture({
      filePath: targetFilePath,
      fileName: request.file.originalname,
      speedMultiplier: payload.speedMultiplier,
    }, getClientCount()).catch(error => {
      console.error('[replay]', error);
    });

    response.json({
      ok: true,
      message: 'Replay accepted.',
    });
  } catch (error) {
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Failed to start replay.',
    });
  }
});

app.get('/api/logs', (request, response) => {
  const limit = Number(request.query.limit || 500);
  const sensorId = typeof request.query.sensorId === 'string' && request.query.sensorId.trim() ? request.query.sensorId.trim() : null;
  response.json({
    logs: listRecentLogs(limit, sensorId),
  });
});

app.get('/api/traffic', (request, response) => {
  const limit = Number(request.query.limit || 100);
  const sensorId = typeof request.query.sensorId === 'string' && request.query.sensorId.trim() ? request.query.sensorId.trim() : null;
  response.json({
    traffic: listRecentTrafficEvents(limit, sensorId),
  });
});

app.get('/api/metrics', (request, response) => {
  const hours = Number(request.query.hours || 24);
  const bucketMinutes = Number(request.query.bucketMinutes || 15);
  const sensorId = typeof request.query.sensorId === 'string' && request.query.sensorId.trim() ? request.query.sensorId.trim() : null;
  response.json({
    snapshot: {
      ...getTrafficCounters(sensorId),
      lastUpdatedAt: new Date().toISOString(),
    },
    series: listTrafficMetrics(hours, bucketMinutes, sensorId),
  });
});

app.get('/api/pcap-artifacts', (request, response) => {
  const limit = Number(request.query.limit || 50);
  const sensorId = typeof request.query.sensorId === 'string' && request.query.sensorId.trim() ? request.query.sensorId.trim() : null;
  response.json({
    artifacts: listPcapArtifacts(limit, sensorId),
  });
});

app.get('/api/pcap-artifacts/:artifactId/download', (request, response) => {
  const artifact = getPcapArtifactById(request.params.artifactId);
  if (!artifact) {
    response.status(404).json({
      ok: false,
      error: 'Artifact not found.',
    });
    return;
  }

  response.download(artifact.filePath, artifact.fileName);
});

app.get('/api/fleet/sensors', (_, response) => {
  response.json({
    sensors: listSensors(),
    fleetStatus: monitoringService.getFleetStatus(),
  });
});

app.get('/api/threat-intel/status', (_, response) => {
  response.json({
    status: monitoringService.threatIntelStatus,
  });
});

app.post('/api/threat-intel/refresh', async (_, response) => {
  try {
    const status = await monitoringService.refreshThreatIntel();
    response.json({
      ok: true,
      status,
    });
  } catch (error) {
    response.status(500).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Threat intelligence refresh failed.',
    });
  }
});

app.post('/api/forensics/chat', async (request, response) => {
  try {
    const payload = forensicsSchema.parse(request.body);
    const result = await monitoringService.runThreatHunt({
      question: payload.question,
      sensorId: payload.sensorId || null,
    });
    response.json({
      ok: true,
      result,
    });
  } catch (error) {
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Threat hunting request failed.',
    });
  }
});

app.post('/api/local-process/open-path', async (request, response) => {
  try {
    const payload = openLocalPathSchema.parse(request.body);
    const revealedPath = await revealLocalPath(payload.path);
    response.json({
      ok: true,
      revealedPath,
    });
  } catch (error) {
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Failed to open local path.',
    });
  }
});

const websocketServer = new WebSocketServer({ noServer: true });
websocketServer.on('connection', socket => {
  wsClients.add(socket);
  socket.send(JSON.stringify({
    type: 'capture-status',
    payload: monitoringService.decorateCaptureStatus(monitoringService.captureAgent.getStatus(getClientCount())),
  }));
  socket.send(JSON.stringify({
    type: 'metrics-update',
    payload: monitoringService.metricSnapshot,
  }));
  socket.send(JSON.stringify({
    type: 'replay-status',
    payload: monitoringService.replayStatus,
  }));
  socket.send(JSON.stringify({
    type: 'fleet-status',
    payload: monitoringService.getFleetStatus(),
  }));
  socket.send(JSON.stringify({
    type: 'threat-intel-status',
    payload: monitoringService.threatIntelStatus,
  }));

  socket.on('close', () => {
    wsClients.delete(socket);
  });
});

const fleetWebsocketServer = new WebSocketServer({ noServer: true });
fleetWebsocketServer.on('connection', (socket, request) => {
  monitoringService.fleetService.handleHubConnection(socket, request);
});

server.on('upgrade', (request, socket, head) => {
  const requestUrl = new URL(request.url, 'http://localhost');

  if (requestUrl.pathname === '/traffic') {
    websocketServer.handleUpgrade(request, socket, head, upgradedSocket => {
      websocketServer.emit('connection', upgradedSocket, request);
    });
    return;
  }

  if (requestUrl.pathname === '/fleet/agent') {
    fleetWebsocketServer.handleUpgrade(request, socket, head, upgradedSocket => {
      fleetWebsocketServer.emit('connection', upgradedSocket, request);
    });
    return;
  }

  socket.destroy();
});

server.listen(PORT, () => {
  console.log(`NetGuard backend listening on http://localhost:${PORT}`);
});

const shutdown = () => {
  monitoringService.stopCapture(getClientCount());
  monitoringService.fleetService.stop();
  monitoringService.threatIntelService.stop();
  websocketServer.close();
  fleetWebsocketServer.close();
  server.close(() => {
    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

```

## File: `server/llmProviders.js`  
- Path: `server/llmProviders.js`  
- Size: 342 Bytes  
- Modified: 2026-03-13 12:03:00 UTC

```javascript
import { PROVIDER_DEFINITIONS } from './defaultConfig.js';

const providerMap = new Map(PROVIDER_DEFINITIONS.map(definition => [definition.id, definition]));

export const getProviderDefinition = (providerId) => providerMap.get(providerId);

export const getSelectedProviderSettings = (config) => config.providerSettings[config.llmProvider];

```

## File: `server/llmService.js`  
- Path: `server/llmService.js`  
- Size: 11575 Bytes  
- Modified: 2026-03-13 13:02:30 UTC

```javascript
import { GoogleGenAI, Type } from '@google/genai';
import { preparePacketForLlm } from './dataScrubber.js';
import { getProviderDefinition, getSelectedProviderSettings } from './llmProviders.js';

const ATTACK_TYPES = ['port_scan', 'brute_force', 'malicious_payload', 'ddos', 'none', 'other'];
const ANALYSIS_SYSTEM_PROMPT = `You are an expert network security analyst.
Return strictly valid raw JSON and nothing else.

Use one of these attack types:
- port_scan
- brute_force
- malicious_payload
- ddos
- none
- other

Confidence must be a number between 0.0 and 1.0.
Explain the decision in one concise sentence. Prefer structured metadata over raw payload when available.`;

const buildPacketProjection = (packet, config, definition) => {
  const prepared = preparePacketForLlm(packet, config, definition);

  return {
    packet_id: packet.id,
    timestamp: packet.timestamp,
    direction: packet.direction,
    capture_device: packet.captureDevice,
    sensor_id: packet.sensorId ?? '',
    sensor_name: packet.sensorName ?? '',
    source_ip: packet.sourceIp,
    source_port: packet.sourcePort,
    destination_ip: packet.destinationIp,
    destination_port: packet.destinationPort,
    protocol: packet.protocol,
    size: packet.size,
    layer7_protocol: packet.l7Protocol,
    layer7_metadata: prepared.l7Metadata,
    payload_snippet_text: prepared.payloadText,
    payload_snippet_hex: prepared.payloadHex,
    masking: prepared.masking,
  };
};

const buildSinglePacketPrompt = (packet, config, definition) =>
  `Analyze this captured network packet and return one JSON object.\n\n${JSON.stringify(buildPacketProjection(packet, config, definition), null, 2)}`;

const buildBatchPrompt = (packets, config, definition) =>
  `Analyze these captured network packets and return one JSON array with one result per packet.
Each result must include:
- packet_id
- is_suspicious
- attack_type
- confidence
- explanation

Packets:
${JSON.stringify(packets.map(packet => buildPacketProjection(packet, config, definition)), null, 2)}`;

const singleResponseSchema = {
  type: Type.OBJECT,
  properties: {
    is_suspicious: { type: Type.BOOLEAN },
    attack_type: { type: Type.STRING, enum: ATTACK_TYPES },
    confidence: { type: Type.NUMBER },
    explanation: { type: Type.STRING },
  },
  required: ['is_suspicious', 'attack_type', 'confidence', 'explanation'],
};

const batchResponseSchema = {
  type: Type.ARRAY,
  items: {
    type: Type.OBJECT,
    properties: {
      packet_id: { type: Type.STRING },
      is_suspicious: { type: Type.BOOLEAN },
      attack_type: { type: Type.STRING, enum: ATTACK_TYPES },
      confidence: { type: Type.NUMBER },
      explanation: { type: Type.STRING },
    },
    required: ['packet_id', 'is_suspicious', 'attack_type', 'confidence', 'explanation'],
  },
};

const isObject = value => typeof value === 'object' && value !== null && !Array.isArray(value);

const clampConfidence = value => {
  const numericValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numericValue)) {
    return 0;
  }
  return Math.max(0, Math.min(1, numericValue));
};

const normalizeAttackType = value => {
  const normalizedValue = typeof value === 'string' ? value.toLowerCase() : 'none';
  return ATTACK_TYPES.includes(normalizedValue) ? normalizedValue : 'none';
};

const parseJsonPayload = content => {
  const trimmed = content.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const arrayStart = trimmed.indexOf('[');
    const objectStart = trimmed.indexOf('{');
    const startIndex = arrayStart !== -1 && (objectStart === -1 || arrayStart < objectStart) ? arrayStart : objectStart;
    const endIndex = Math.max(trimmed.lastIndexOf(']'), trimmed.lastIndexOf('}'));
    if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
      throw new Error('Provider response did not contain valid JSON.');
    }
    return JSON.parse(trimmed.slice(startIndex, endIndex + 1));
  }
};

const normalizeAnalysisResult = (packet, payload, decisionSource = 'llm') => ({
  isSuspicious: Boolean(payload.is_suspicious ?? payload.isSuspicious ?? false),
  attackType: normalizeAttackType(payload.attack_type ?? payload.attackType),
  confidence: clampConfidence(payload.confidence),
  explanation:
    typeof payload.explanation === 'string' && payload.explanation.trim()
      ? payload.explanation.trim()
      : 'Analysis incomplete.',
  packet,
  decisionSource,
  matchedSignals: [],
});

const defaultBenign = (packet, explanation) => ({
  isSuspicious: false,
  attackType: 'none',
  confidence: 0,
  explanation,
  packet,
  decisionSource: 'llm',
  matchedSignals: [],
});

const ensureApiKey = definition => {
  if (!definition.requiresApiKey) {
    return '';
  }

  const apiKey = process.env[definition.envVar] || '';
  if (!apiKey) {
    throw new Error(`${definition.label} API key is not configured in ${definition.envVar}.`);
  }
  return apiKey;
};

const normalizeBaseUrl = (baseUrl, transport) => {
  const trimmedBaseUrl = baseUrl.trim().replace(/\/+$/, '');
  if (transport === 'openai-compatible') {
    return trimmedBaseUrl.replace(/\/chat\/completions$/i, '');
  }
  if (transport === 'anthropic') {
    return trimmedBaseUrl.replace(/\/v1\/messages$/i, '');
  }
  if (transport === 'ollama') {
    return trimmedBaseUrl.replace(/\/api\/chat$/i, '');
  }
  return trimmedBaseUrl;
};

const joinUrl = (baseUrl, path) => `${baseUrl.replace(/\/+$/, '')}${path}`;

const requestGemini = async (model, systemPrompt, prompt, schema, definition) => {
  const client = new GoogleGenAI({ apiKey: ensureApiKey(definition) });
  const response = await client.models.generateContent({
    model,
    contents: `${systemPrompt}\n\n${prompt}`,
    config: {
      responseMimeType: 'application/json',
      responseSchema: schema,
      temperature: 0.1,
    },
  });
  return parseJsonPayload(response.text);
};

const requestOpenAiCompatible = async (model, baseUrl, systemPrompt, prompt, definition) => {
  const headers = {
    'Content-Type': 'application/json',
  };

  if (definition.requiresApiKey) {
    headers.Authorization = `Bearer ${ensureApiKey(definition)}`;
  }

  const response = await fetch(joinUrl(baseUrl, '/chat/completions'), {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt },
      ],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    throw new Error(`Provider responded with ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const responseContent = data?.choices?.[0]?.message?.content;
  if (typeof responseContent !== 'string') {
    throw new Error('Provider returned an invalid response.');
  }
  return parseJsonPayload(responseContent);
};

const requestAnthropic = async (model, baseUrl, systemPrompt, prompt, definition) => {
  const response = await fetch(joinUrl(baseUrl, '/v1/messages'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ensureApiKey(definition),
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      system: systemPrompt,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1600,
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    throw new Error(`Anthropic responded with ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const responseContent = Array.isArray(data?.content)
    ? data.content
        .filter(item => item?.type === 'text' && typeof item.text === 'string')
        .map(item => item.text)
        .join('\n')
    : '';

  if (!responseContent) {
    throw new Error('Anthropic returned an invalid response.');
  }

  return parseJsonPayload(responseContent);
};

const requestOllama = async (model, baseUrl, systemPrompt, prompt) => {
  const response = await fetch(joinUrl(baseUrl, '/api/chat'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      stream: false,
      format: 'json',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama responded with ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const responseContent = data?.message?.content;
  if (typeof responseContent !== 'string') {
    throw new Error('Ollama returned an invalid response.');
  }
  return parseJsonPayload(responseContent);
};

export const getProviderRuntime = config => {
  const definition = getProviderDefinition(config.llmProvider);
  const providerSettings = getSelectedProviderSettings(config);
  return {
    definition,
    model: providerSettings.model || definition.defaultModel,
    baseUrl: normalizeBaseUrl(providerSettings.baseUrl || definition.defaultBaseUrl, definition.transport),
  };
};

export const requestProviderJson = async (config, prompt, schema, options = {}) => {
  const runtime = getProviderRuntime(config);
  const systemPrompt = options.systemPrompt || ANALYSIS_SYSTEM_PROMPT;

  switch (runtime.definition.transport) {
    case 'gemini':
      return requestGemini(runtime.model, systemPrompt, prompt, schema, runtime.definition);
    case 'openai-compatible':
      return requestOpenAiCompatible(runtime.model, runtime.baseUrl, systemPrompt, prompt, runtime.definition);
    case 'anthropic':
      return requestAnthropic(runtime.model, runtime.baseUrl, systemPrompt, prompt, runtime.definition);
    case 'ollama':
      return requestOllama(runtime.model, runtime.baseUrl, systemPrompt, prompt);
    default:
      throw new Error(`Unsupported provider transport: ${runtime.definition.transport}`);
  }
};

export const analyzeTraffic = async (packet, config) => {
  try {
    const runtime = getProviderRuntime(config);
    const payload = await requestProviderJson(config, buildSinglePacketPrompt(packet, config, runtime.definition), singleResponseSchema, {
      systemPrompt: ANALYSIS_SYSTEM_PROMPT,
    });
    if (!isObject(payload)) {
      throw new Error('Provider did not return a JSON object.');
    }
    return normalizeAnalysisResult(packet, payload);
  } catch (error) {
    return defaultBenign(packet, error instanceof Error ? error.message : 'LLM analysis failed.');
  }
};

export const analyzeTrafficBatch = async (packets, config) => {
  if (packets.length === 0) {
    return [];
  }

  if (packets.length === 1) {
    return [await analyzeTraffic(packets[0], config)];
  }

  try {
    const runtime = getProviderRuntime(config);
    const payload = await requestProviderJson(config, buildBatchPrompt(packets, config, runtime.definition), batchResponseSchema, {
      systemPrompt: ANALYSIS_SYSTEM_PROMPT,
    });
    if (!Array.isArray(payload)) {
      throw new Error('Provider did not return a JSON array.');
    }

    const resultMap = new Map(
      payload.filter(isObject).filter(item => typeof item.packet_id === 'string').map(item => [item.packet_id, item])
    );

    return packets.map(packet => {
      const payloadItem = resultMap.get(packet.id);
      return payloadItem ? normalizeAnalysisResult(packet, payloadItem) : defaultBenign(packet, 'Batch analysis returned no decision for this packet.');
    });
  } catch (error) {
    return Promise.all(packets.map(packet => analyzeTraffic(packet, config)));
  }
};

export { Type };

```

## File: `server/localPathService.js`  
- Path: `server/localPathService.js`  
- Size: 1709 Bytes  
- Modified: 2026-03-13 14:21:22 UTC

```javascript
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const validateLocalPath = (targetPath) => {
  if (typeof targetPath !== 'string' || !targetPath.trim()) {
    throw new Error('A valid path is required.');
  }

  const resolvedPath = path.resolve(targetPath.trim());
  if (!path.isAbsolute(resolvedPath)) {
    throw new Error('Only absolute local paths can be opened.');
  }

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${resolvedPath}`);
  }

  return resolvedPath;
};

const spawnDetached = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      detached: true,
      shell: false,
      stdio: 'ignore',
      windowsHide: true,
    });

    child.on('error', reject);
    child.unref();
    resolve();
  });

export const revealLocalPath = async (targetPath) => {
  const resolvedPath = validateLocalPath(targetPath);
  const stats = fs.statSync(resolvedPath);
  const platform = os.platform();

  if (platform === 'win32') {
    if (stats.isDirectory()) {
      await spawnDetached('explorer.exe', [resolvedPath]);
    } else {
      await spawnDetached('explorer.exe', [`/select,${resolvedPath}`]);
    }
    return resolvedPath;
  }

  if (platform === 'darwin') {
    await spawnDetached('open', stats.isDirectory() ? [resolvedPath] : ['-R', resolvedPath]);
    return resolvedPath;
  }

  if (platform === 'linux') {
    await spawnDetached('xdg-open', [stats.isDirectory() ? resolvedPath : path.dirname(resolvedPath)]);
    return resolvedPath;
  }

  throw new Error(`Opening local paths is not supported on platform: ${platform}`);
};

```

## File: `server/monitoringService.js`  
- Path: `server/monitoringService.js`  
- Size: 24961 Bytes  
- Modified: 2026-03-13 14:29:16 UTC

```javascript
import crypto from 'node:crypto';
import {
  getServerConfiguration,
  insertLogEntry,
  insertPcapArtifact,
  insertTrafficEvent,
  listPcapArtifacts,
  listRecentLogs,
  listRecentTrafficEvents,
  listSensors,
  listTrafficMetrics,
  saveServerConfiguration,
  getTrafficCounters,
  upsertSensor,
  deleteSensor,
} from './db.js';
import { sanitizeConfigurationForClient } from './configStore.js';
import { CaptureAgent } from './captureAgent.js';
import { AnalysisCoordinator, AnalysisCoordinatorResetError } from './analysisCoordinator.js';
import { HeuristicAnalyzer } from './heuristicAnalyzer.js';
import { dispatchAlertWebhooks } from './webhookDispatcher.js';
import { FirewallManager } from './firewallManager.js';
import { PcapForensics } from './pcapForensics.js';
import { getProviderDefinition } from './llmProviders.js';
import { ThreatIntelService } from './threatIntelService.js';
import { FleetService } from './fleetService.js';
import { ForensicsChatService } from './forensicsChatService.js';
import { ProcessResolver } from './processResolver.js';

const createId = () => crypto.randomUUID();

const createReplayStatus = () => ({
  state: 'idle',
  fileName: null,
  processedPackets: 0,
  totalPackets: 0,
  startedAt: null,
  completedAt: null,
  message: null,
});

export class MonitoringService {
  constructor({ broadcast }) {
    this.broadcast = broadcast;
    this.configuration = getServerConfiguration();
    this.metricSnapshot = {
      ...getTrafficCounters(),
      lastUpdatedAt: new Date().toISOString(),
    };
    this.localMetricSnapshot = {
      ...getTrafficCounters(this.configuration.sensorId),
      lastUpdatedAt: new Date().toISOString(),
    };
    this.replayStatus = createReplayStatus();
    this.fleetStatus = {
      deploymentMode: this.configuration.deploymentMode,
      sensorId: this.configuration.sensorId,
      sensorName: this.configuration.sensorName,
      connectedToHub: false,
      connectedSensors: 0,
      hubUrl: this.configuration.hubUrl || null,
      lastSyncAt: null,
      lastError: null,
    };
    this.threatIntelStatus = {
      enabled: this.configuration.threatIntelEnabled,
      loadedIndicators: 0,
      sourceCount: this.configuration.threatIntelSources.length,
      lastRefreshAt: null,
      lastError: null,
      refreshing: false,
    };
    this.captureAgent = new CaptureAgent({
      onPacket: decodedPacket => {
        void this.processDecodedPacketSafely(decodedPacket, { source: 'live' });
      },
      onStatus: status => {
        const payload = this.decorateCaptureStatus(status);
        this.broadcast({
          type: 'capture-status',
          payload,
        });
        this.fleetService.publishCaptureStatus(payload);
        this.upsertLocalSensor();
      },
      onError: error => {
        this.emitLog('ERROR', 'Packet capture error', { error: error.message });
        this.broadcast({
          type: 'capture-error',
          payload: {
            message: error.message,
          },
        });
      },
    });
    this.analysisCoordinator = new AnalysisCoordinator();
    this.heuristicAnalyzer = new HeuristicAnalyzer();
    this.firewallManager = new FirewallManager();
    this.pcapForensics = new PcapForensics();
    this.forensicsChatService = new ForensicsChatService();
    this.processResolver = new ProcessResolver({
      onError: error => {
        this.emitLog('WARN', 'Local process resolution failed.', {
          error: error instanceof Error ? error.message : 'Unknown process resolution error',
        });
      },
    });
    this.threatIntelService = new ThreatIntelService({
      onStatusChange: status => {
        this.threatIntelStatus = status;
        this.broadcast({
          type: 'threat-intel-status',
          payload: status,
        });
      },
      onLog: (level, message, details) => {
        this.emitLog(level, message, details);
      },
    });
    this.fleetService = new FleetService({
      getConfiguration: () => this.configuration,
      onSensorUpdate: summary => {
        upsertSensor(summary);
        this.broadcast({
          type: 'sensor-update',
          payload: summary,
        });
      },
      onFleetStatus: status => {
        this.fleetStatus = {
          ...status,
          connectedSensors: listSensors().filter(sensor => !sensor.local && sensor.connected).length,
        };
        this.broadcast({
          type: 'fleet-status',
          payload: this.fleetStatus,
        });
      },
      onRemoteTraffic: (entry, sensorSummary) => {
        this.ingestRemoteTrafficEvent(entry, sensorSummary);
      },
      onRemoteLog: (entry, sensorSummary) => {
        this.ingestRemoteLogEntry(entry, sensorSummary);
      },
      onRemoteArtifact: (artifact, sensorSummary) => {
        this.ingestRemoteArtifact(artifact, sensorSummary);
      },
      onGlobalBlock: (ipAddress, details) => {
        void this.applyExternalBlock(ipAddress, details);
      },
    });
    this.threatIntelService.configure(this.configuration);
    this.fleetService.configure(this.configuration);
    this.upsertLocalSensor();
  }

  decorateCaptureStatus(status) {
    return {
      ...status,
      replayActive: this.replayStatus.state === 'running',
      sensorId: this.configuration.sensorId,
      sensorName: this.configuration.sensorName,
    };
  }

  upsertLocalSensor() {
    const localSummary = {
      id: this.configuration.sensorId,
      name: this.configuration.sensorName,
      mode: this.configuration.deploymentMode,
      connected: this.configuration.deploymentMode === 'agent' ? this.fleetStatus.connectedToHub : true,
      hubUrl: this.configuration.hubUrl || null,
      lastSeenAt: new Date().toISOString(),
      captureRunning: this.captureAgent.getStatus().running,
      packetsProcessed: this.localMetricSnapshot.packetsProcessed,
      threatsDetected: this.localMetricSnapshot.threatsDetected,
      blockedDecisions: this.localMetricSnapshot.blockedDecisions,
      lastEventAt: this.localMetricSnapshot.lastUpdatedAt,
      local: true,
    };
    upsertSensor(localSummary);
    this.broadcast({
      type: 'sensor-update',
      payload: localSummary,
    });
  }

  getClientConfiguration() {
    return sanitizeConfigurationForClient(this.configuration);
  }

  updateConfiguration(nextConfiguration) {
    const previousSensorId = this.configuration.sensorId;
    const mergedProviderSettings = {
      ...this.configuration.providerSettings,
      ...(nextConfiguration.providerSettings ?? {}),
    };

    for (const [providerId, existingSettings] of Object.entries(this.configuration.providerSettings)) {
      const incomingSettings = mergedProviderSettings[providerId];
      if (!incomingSettings) {
        mergedProviderSettings[providerId] = existingSettings;
        continue;
      }

      mergedProviderSettings[providerId] = {
        ...existingSettings,
        ...incomingSettings,
        apiKey: incomingSettings.apiKey || existingSettings.apiKey || '',
      };
    }

    this.configuration = saveServerConfiguration({
      ...this.configuration,
      ...nextConfiguration,
      fleetSharedToken: nextConfiguration.fleetSharedToken || this.configuration.fleetSharedToken || '',
      providerSettings: mergedProviderSettings,
    });
    if (previousSensorId !== this.configuration.sensorId) {
      deleteSensor(previousSensorId);
    }
    this.syncMetricSnapshots();
    this.threatIntelService.configure(this.configuration);
    this.fleetService.configure(this.configuration);
    this.upsertLocalSensor();
    this.emitLog('INFO', 'Configuration updated', {
      llmProvider: this.configuration.llmProvider,
      deploymentMode: this.configuration.deploymentMode,
      threatIntelEnabled: this.configuration.threatIntelEnabled,
      payloadMaskingMode: this.configuration.payloadMaskingMode,
      liveRawFeedEnabled: this.configuration.liveRawFeedEnabled,
      firewallIntegrationEnabled: this.configuration.firewallIntegrationEnabled,
      customRuleCount: this.configuration.customRules.length,
    });
    return this.getClientConfiguration();
  }

  getFleetStatus() {
    const sensors = listSensors();
    return {
      ...this.fleetService.getStatus(),
      connectedSensors: sensors.filter(sensor => !sensor.local && sensor.connected).length,
    };
  }

  syncMetricSnapshots() {
    this.metricSnapshot = {
      ...getTrafficCounters(),
      lastUpdatedAt: new Date().toISOString(),
    };
    this.localMetricSnapshot = {
      ...getTrafficCounters(this.configuration.sensorId),
      lastUpdatedAt: new Date().toISOString(),
    };
    this.broadcast({
      type: 'metrics-update',
      payload: this.metricSnapshot,
    });
    this.fleetService.publishMetrics(this.localMetricSnapshot);
    this.upsertLocalSensor();
  }

  getBootstrapPayload(clientCount = 0, sensorId = null) {
    const sensors = listSensors();
    return {
      config: this.getClientConfiguration(),
      interfaces: this.captureAgent.listInterfaces(),
      captureStatus: this.decorateCaptureStatus(this.captureAgent.getStatus(clientCount)),
      metrics: {
        ...getTrafficCounters(sensorId),
        lastUpdatedAt: new Date().toISOString(),
      },
      metricSeries: listTrafficMetrics(24, 15, sensorId),
      traffic: listRecentTrafficEvents(100, sensorId),
      logs: listRecentLogs(500, sensorId),
      artifacts: listPcapArtifacts(50, sensorId),
      replayStatus: this.replayStatus,
      fleetStatus: {
        ...this.fleetService.getStatus(),
        connectedSensors: sensors.filter(sensor => !sensor.local && sensor.connected).length,
      },
      sensors,
      threatIntelStatus: this.threatIntelStatus,
    };
  }

  emitLog(level, message, details, overrides = {}) {
    const logEntry = insertLogEntry({
      id: createId(),
      timestamp: new Date().toISOString(),
      level,
      message,
      details,
      sensorId: overrides.sensorId ?? this.configuration.sensorId,
      sensorName: overrides.sensorName ?? this.configuration.sensorName,
    });
    this.broadcast({
      type: 'log-entry',
      payload: logEntry,
    });
    if ((overrides.sensorId ?? this.configuration.sensorId) === this.configuration.sensorId) {
      this.fleetService.publishLog(logEntry);
    }
    return logEntry;
  }

  async startCapture(payload, clientCount = 0) {
    if (this.replayStatus.state === 'running') {
      throw new Error('Historical replay is running. Stop replay before starting live capture.');
    }

    this.analysisCoordinator.reset('Capture started.');
    this.heuristicAnalyzer.reset();
    this.pcapForensics.reset();
    const status = await this.captureAgent.start(payload, clientCount);
    this.emitLog('INFO', 'Network monitoring started.', {
      device: status.activeDevice,
      filter: status.activeFilter,
    });
    return this.decorateCaptureStatus(status);
  }

  stopCapture(clientCount = 0) {
    const status = this.captureAgent.stop(clientCount);
    this.analysisCoordinator.reset('Capture stopped.');
    this.heuristicAnalyzer.reset();
    this.pcapForensics.reset();
    this.emitLog('INFO', 'Network monitoring stopped.');
    return this.decorateCaptureStatus(status);
  }

  async replayCapture({ filePath, fileName, speedMultiplier }, clientCount = 0) {
    if (this.captureAgent.getStatus(clientCount).running) {
      throw new Error('Stop live capture before starting replay.');
    }

    this.analysisCoordinator.reset('Replay started.');
    this.heuristicAnalyzer.reset();
    this.pcapForensics.reset();
    this.captureAgent.setReplayActive(true, clientCount);
    this.replayStatus = {
      ...createReplayStatus(),
      state: 'running',
      fileName,
      startedAt: new Date().toISOString(),
    };
    this.broadcast({ type: 'replay-status', payload: this.replayStatus });
    this.emitLog('INFO', 'Historical replay started.', { fileName, speedMultiplier });

    try {
      await this.pcapForensics.replayPcap({
        filePath,
        fileName,
        speedMultiplier,
        onStatus: statusUpdate => {
          this.replayStatus = {
            ...this.replayStatus,
            ...statusUpdate,
            startedAt: this.replayStatus.startedAt,
          };
          this.broadcast({ type: 'replay-status', payload: this.replayStatus });
        },
        onPacket: async decodedPacket => {
          await this.processDecodedPacketSafely(decodedPacket, { source: 'replay' });
        },
      });
      this.emitLog('INFO', 'Historical replay completed.', { fileName });
    } catch (error) {
      this.replayStatus = {
        ...this.replayStatus,
        state: 'failed',
        completedAt: new Date().toISOString(),
        message: error instanceof Error ? error.message : 'Replay failed.',
      };
      this.broadcast({ type: 'replay-status', payload: this.replayStatus });
      this.emitLog('ERROR', 'Historical replay failed.', {
        fileName,
        error: error instanceof Error ? error.message : 'Replay failed.',
      });
      throw error;
    } finally {
      this.captureAgent.setReplayActive(false, clientCount);
      if (this.replayStatus.state !== 'failed') {
        this.replayStatus = {
          ...this.replayStatus,
          state: 'completed',
          completedAt: new Date().toISOString(),
        };
        this.broadcast({ type: 'replay-status', payload: this.replayStatus });
      }
    }
  }

  async processDecodedPacket(decodedPacket, { source }) {
    const packet = {
      ...decodedPacket.packet,
      sensorId: this.configuration.sensorId,
      sensorName: this.configuration.sensorName,
    };
    packet.localProcess = await this.processResolver.resolvePacket(packet);
    delete packet.payloadBuffer;

    this.pcapForensics.rememberFrame({
      rawFrame: decodedPacket.rawFrame,
      timestampMicros: Date.parse(packet.timestamp) * 1000,
      packetId: packet.id,
    }, this.configuration.pcapBufferSize);

    if (this.configuration.liveRawFeedEnabled) {
      this.broadcast({
        type: 'raw-packet',
        payload: packet,
      });
    }

    const decision = await this.analyzePacket(packet, source);
    const trafficEntry = insertTrafficEvent(decision);
    this.syncMetricSnapshots();
    this.broadcast({
      type: 'traffic-event',
      payload: trafficEntry,
    });
    this.fleetService.publishTraffic(trafficEntry);

    if (trafficEntry.isSuspicious) {
      this.broadcast({
        type: 'threat-detected',
        payload: trafficEntry,
      });
    }
  }

  async processDecodedPacketSafely(decodedPacket, context) {
    try {
      await this.processDecodedPacket(decodedPacket, context);
    } catch (error) {
      if (error instanceof AnalysisCoordinatorResetError || error?.code === 'ANALYSIS_QUEUE_RESET') {
        return;
      }

      this.emitLog('ERROR', 'Packet analysis failed.', {
        error: error instanceof Error ? error.message : 'Unknown packet analysis error',
        source: context.source,
        packetId: decodedPacket?.packet?.id ?? null,
        sourceIp: decodedPacket?.packet?.sourceIp ?? null,
        destinationPort: decodedPacket?.packet?.destinationPort ?? null,
      });
    }
  }

  async applyExternalBlock(ipAddress, details = {}) {
    if (!this.configuration.blockedIps.includes(ipAddress)) {
      this.configuration.blockedIps.push(ipAddress);
      saveServerConfiguration(this.configuration);
    }

    let firewallApplied = false;
    if (this.configuration.firewallIntegrationEnabled) {
      try {
        const firewallResult = await this.firewallManager.blockIp(ipAddress);
        firewallApplied = firewallResult.applied;
      } catch (error) {
        this.emitLog('ERROR', 'Fleet block firewall enforcement failed.', {
          ipAddress,
          error: error instanceof Error ? error.message : 'Unknown firewall error',
        });
      }
    }

    this.emitLog('CRITICAL', `Fleet block applied for ${ipAddress}`, {
      ipAddress,
      reason: details.reason || 'Global block propagation',
      firewallApplied,
    });
  }

  async analyzePacket(packet, source) {
    let analysisResult;
    let actionType = 'ALLOW';
    let actionLabel = 'Allow';
    let firewallApplied = false;
    let pcapArtifactId = null;

    if (this.configuration.exemptPorts.includes(packet.destinationPort)) {
      analysisResult = {
        isSuspicious: false,
        attackType: 'none',
        confidence: 0,
        explanation: 'Traffic allowed because the destination port is exempt.',
        packet,
        decisionSource: 'exempt',
        matchedSignals: [],
      };
    } else if (this.configuration.blockedIps.includes(packet.sourceIp) || this.configuration.blockedPorts.includes(packet.destinationPort)) {
      analysisResult = {
        isSuspicious: true,
        attackType: 'other',
        confidence: 1,
        explanation: 'Traffic matched an explicit blocklist rule.',
        packet,
        decisionSource: 'blocklist',
        matchedSignals: ['policy.blocklist'],
        recommendedActionType: 'BLOCK',
      };
      actionType = 'BLOCK';
      actionLabel = 'Block';
    } else {
      const threatIntelMatch = this.configuration.threatIntelEnabled ? this.threatIntelService.lookupIp(packet.sourceIp) : null;
      if (threatIntelMatch) {
        analysisResult = {
          isSuspicious: true,
          attackType: 'other',
          confidence: threatIntelMatch.confidence,
          explanation: `Source IP matched threat intelligence feed ${threatIntelMatch.sourceName}.`,
          packet,
          decisionSource: 'threat_intel',
          matchedSignals: [`threat_intel:${threatIntelMatch.sourceName}`, threatIntelMatch.indicator],
          recommendedActionType: this.configuration.threatIntelAutoBlock ? 'BLOCK' : 'ALLOW',
        };
      } else {
        const heuristicEvaluation = this.heuristicAnalyzer.evaluate(packet, this.configuration);

        if (heuristicEvaluation.result && !heuristicEvaluation.needsDeepInspection) {
          analysisResult = heuristicEvaluation.result;
        } else {
          analysisResult = await this.analysisCoordinator.analyze(packet, this.configuration);
        }
      }

      if (analysisResult.recommendedActionType) {
        actionType = analysisResult.recommendedActionType;
        actionLabel = actionType === 'REDIRECT' ? `Redirect (${analysisResult.recommendedTargetPort ?? this.configuration.securePort})` : actionType === 'BLOCK' ? 'Block' : 'Allow';
      } else if (analysisResult.isSuspicious && analysisResult.confidence >= this.configuration.detectionThreshold) {
        if (analysisResult.attackType === 'malicious_payload') {
          actionType = 'REDIRECT';
          actionLabel = `Redirect (${this.configuration.securePort})`;
        } else {
          actionType = 'BLOCK';
          actionLabel = 'Block';
        }
      }
    }

    if (actionType === 'BLOCK' && this.configuration.autoBlockThreats && !this.configuration.blockedIps.includes(packet.sourceIp)) {
      this.configuration.blockedIps.push(packet.sourceIp);
      saveServerConfiguration(this.configuration);
      this.emitLog('WARN', `IP ${packet.sourceIp} auto-added to blocklist`, {
        sourceIp: packet.sourceIp,
      });
    }

    if (actionType === 'BLOCK' && this.configuration.firewallIntegrationEnabled) {
      try {
        const firewallResult = await this.firewallManager.blockIp(packet.sourceIp);
        firewallApplied = firewallResult.applied;
        this.emitLog('WARN', 'Firewall enforcement executed.', firewallResult);
      } catch (error) {
        this.emitLog('ERROR', 'Firewall enforcement failed.', {
          sourceIp: packet.sourceIp,
          error: error instanceof Error ? error.message : 'Unknown firewall error',
        });
      }
    }

    if (analysisResult.isSuspicious || actionType === 'BLOCK' || actionType === 'REDIRECT') {
      this.emitLog(actionType === 'BLOCK' ? 'CRITICAL' : 'WARN', 'Threat detected.', {
        sourceIp: packet.sourceIp,
        destinationPort: packet.destinationPort,
        attackType: analysisResult.attackType,
        confidence: analysisResult.confidence,
        actionType,
        decisionSource: analysisResult.decisionSource,
      });

      const artifact = await this.pcapForensics.exportThreatWindow({
        packetCount: this.configuration.pcapBufferSize,
        attackType: analysisResult.attackType,
        sourceIp: packet.sourceIp,
        explanation: analysisResult.explanation,
        threatEventId: packet.id,
      });

      if (artifact) {
        const persistedArtifact = insertPcapArtifact({
          ...artifact,
          sensorId: this.configuration.sensorId,
          sensorName: this.configuration.sensorName,
        });
        pcapArtifactId = persistedArtifact.id;
        const artifactPayload = {
          id: persistedArtifact.id,
          createdAt: persistedArtifact.createdAt,
          fileName: persistedArtifact.fileName,
          attackType: persistedArtifact.attackType,
          sourceIp: persistedArtifact.sourceIp,
          packetCount: persistedArtifact.packetCount,
          explanation: persistedArtifact.explanation,
          bytes: persistedArtifact.bytes,
          sensorId: this.configuration.sensorId,
          sensorName: this.configuration.sensorName,
        };
        this.broadcast({
          type: 'pcap-artifact',
          payload: artifactPayload,
        });
        this.fleetService.publishArtifact(artifactPayload);
      }
    }

    if (analysisResult.isSuspicious || actionType === 'BLOCK' || actionType === 'REDIRECT') {
      const enabledWebhooks = this.configuration.webhookIntegrations.filter(destination => destination.enabled && destination.url);
      if (enabledWebhooks.length > 0) {
        try {
          await dispatchAlertWebhooks(enabledWebhooks, {
            timestamp: packet.timestamp,
            severity: actionType === 'BLOCK' ? 'critical' : 'warning',
            action: actionType,
            sourceIp: packet.sourceIp,
            sourcePort: packet.sourcePort,
            destinationIp: packet.destinationIp,
            destinationPort: packet.destinationPort,
            attackType: analysisResult.attackType,
            confidence: analysisResult.confidence,
            explanation: analysisResult.explanation,
            provider: getProviderDefinition(this.configuration.llmProvider)?.label ?? this.configuration.llmProvider,
            sensorId: this.configuration.sensorId,
            sensorName: this.configuration.sensorName,
          });
        } catch (error) {
          this.emitLog('ERROR', 'Webhook dispatch failed.', {
            error: error instanceof Error ? error.message : 'Unknown webhook error',
          });
        }
      }
    }

    if (actionType === 'BLOCK' && this.configuration.globalBlockPropagationEnabled) {
      this.fleetService.propagateGlobalBlock(packet.sourceIp, {
        reason: analysisResult.explanation,
      });
    }

    return {
      id: packet.id,
      ...analysisResult,
      decisionSource: source === 'replay' ? 'replay' : analysisResult.decisionSource,
      action: actionLabel,
      actionType,
      createdAt: new Date().toISOString(),
      firewallApplied,
      pcapArtifactId,
      sensorId: this.configuration.sensorId,
      sensorName: this.configuration.sensorName,
    };
  }

  ingestRemoteTrafficEvent(entry, sensorSummary) {
    const hydratedEntry = {
      ...entry,
      sensorId: sensorSummary.id,
      sensorName: sensorSummary.name,
      packet: {
        ...(entry.packet ?? {}),
        sensorId: sensorSummary.id,
        sensorName: sensorSummary.name,
      },
    };

    insertTrafficEvent(hydratedEntry);
    this.broadcast({
      type: 'traffic-event',
      payload: hydratedEntry,
    });
    if (hydratedEntry.isSuspicious) {
      this.broadcast({
        type: 'threat-detected',
        payload: hydratedEntry,
      });
    }
    this.syncMetricSnapshots();
  }

  ingestRemoteLogEntry(entry, sensorSummary) {
    const hydratedEntry = insertLogEntry({
      ...entry,
      sensorId: sensorSummary.id,
      sensorName: sensorSummary.name,
    });
    this.broadcast({
      type: 'log-entry',
      payload: hydratedEntry,
    });
  }

  ingestRemoteArtifact(artifact, sensorSummary) {
    const hydratedArtifact = insertPcapArtifact({
      ...artifact,
      sensorId: sensorSummary.id,
      sensorName: sensorSummary.name,
    });
    this.broadcast({
      type: 'pcap-artifact',
      payload: {
        ...hydratedArtifact,
        sensorId: sensorSummary.id,
        sensorName: sensorSummary.name,
      },
    });
  }

  async refreshThreatIntel() {
    return this.threatIntelService.refresh(this.configuration);
  }

  async runThreatHunt({ question, sensorId }) {
    return this.forensicsChatService.runQuestion({
      question,
      sensorId,
      config: this.configuration,
    });
  }
}

```

## File: `server/pcapForensics.js`  
- Path: `server/pcapForensics.js`  
- Size: 4410 Bytes  
- Modified: 2026-03-13 12:04:54 UTC

```javascript
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import pcapWriterModule from 'pcap-writer';
import pcapParserModule from 'pcap-parser';
import { directories } from './db.js';
import { decodePacketFrame } from './captureAgent.js';

const { createPcapWriter } = pcapWriterModule;
const { parse: parsePcap } = pcapParserModule;
const PCAP_LINKTYPE_ETHERNET = 1;

const wait = (durationMs) => new Promise(resolve => setTimeout(resolve, durationMs));

export class PcapForensics {
  constructor() {
    this.recentFrames = [];
  }

  reset() {
    this.recentFrames = [];
  }

  rememberFrame(frameRecord, maxFrames) {
    this.recentFrames.push(frameRecord);
    if (this.recentFrames.length > maxFrames) {
      this.recentFrames.shift();
    }
  }

  async exportThreatWindow({ packetCount, attackType, sourceIp, explanation, threatEventId }) {
    const exportFrames = this.recentFrames.slice(-packetCount);
    if (exportFrames.length === 0) {
      return null;
    }

    const artifactId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const safeSourceIp = sourceIp.replace(/[:.]/g, '_');
    const fileName = `${createdAt.replace(/[:.]/g, '-')}_${safeSourceIp}_${attackType}.pcap`;
    const filePath = path.join(directories.pcapDirectory, fileName);
    const writer = createPcapWriter(filePath, 65535, PCAP_LINKTYPE_ETHERNET);

    await new Promise((resolve, reject) => {
      try {
        exportFrames.forEach(frame => {
          writer.writePacket(frame.rawFrame, frame.timestampMicros);
        });
        writer.close(() => resolve(null));
      } catch (error) {
        reject(error);
      }
    });

    const stats = fs.statSync(filePath);
    return {
      id: artifactId,
      createdAt,
      fileName,
      filePath,
      attackType,
      sourceIp,
      packetCount: exportFrames.length,
      explanation,
      bytes: stats.size,
      threatEventId,
    };
  }

  async parseReplayFile(filePath) {
    return new Promise((resolve, reject) => {
      const packets = [];
      let linkLayerType = PCAP_LINKTYPE_ETHERNET;
      const parser = parsePcap(filePath);

      parser.on('globalHeader', header => {
        linkLayerType = header.linkLayerType;
      });

      parser.on('packet', packet => {
        packets.push({
          timestampMicros: packet.header.timestampSeconds * 1_000_000 + packet.header.timestampMicroseconds,
          originalLength: packet.header.originalLength,
          rawFrame: packet.data,
          linkLayerType,
        });
      });

      parser.on('end', () => resolve(packets));
      parser.on('error', reject);
    });
  }

  async replayPcap({ filePath, fileName, speedMultiplier = 10, onStatus, onPacket }) {
    const replayPackets = await this.parseReplayFile(filePath);
    const safeSpeed = speedMultiplier > 0 ? speedMultiplier : 10;

    onStatus({
      state: 'running',
      fileName,
      processedPackets: 0,
      totalPackets: replayPackets.length,
      startedAt: new Date().toISOString(),
      completedAt: null,
      message: null,
    });

    let previousTimestamp = replayPackets[0]?.timestampMicros ?? 0;
    for (let index = 0; index < replayPackets.length; index += 1) {
      const replayPacket = replayPackets[index];
      const delayMs = Math.min(Math.max((replayPacket.timestampMicros - previousTimestamp) / 1000 / safeSpeed, 0), 500);
      previousTimestamp = replayPacket.timestampMicros;
      if (delayMs > 0) {
        await wait(delayMs);
      }

      const decodedPacket = decodePacketFrame({
        frame: replayPacket.rawFrame,
        linkType: replayPacket.linkLayerType === PCAP_LINKTYPE_ETHERNET ? 'ETHERNET' : 'UNKNOWN',
        captureDevice: `replay:${fileName}`,
        timestamp: new Date(replayPacket.timestampMicros / 1000).toISOString(),
      });

      if (decodedPacket) {
        await onPacket(decodedPacket);
      }

      onStatus({
        state: 'running',
        fileName,
        processedPackets: index + 1,
        totalPackets: replayPackets.length,
        startedAt: null,
        completedAt: null,
        message: null,
      });
    }

    onStatus({
      state: 'completed',
      fileName,
      processedPackets: replayPackets.length,
      totalPackets: replayPackets.length,
      startedAt: null,
      completedAt: new Date().toISOString(),
      message: null,
    });
  }
}

```

## File: `server/processResolver.js`  
- Path: `server/processResolver.js`  
- Size: 14520 Bytes  
- Modified: 2026-03-13 14:21:22 UTC

```javascript
import os from 'node:os';
import { spawn } from 'node:child_process';

const DEFAULT_REFRESH_INTERVAL_MS = 2_500;
const BINARY_METADATA_TTL_MS = 10 * 60 * 1000;
const PROCESS_QUERY_TIMEOUT_MS = 8_000;
const ERROR_THROTTLE_MS = 60_000;

const WINDOWS_PROCESS_QUERY = `
$tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess)
$processIds = @($tcp.OwningProcess + $udp.OwningProcess | Where-Object { $_ -ne $null } | Sort-Object -Unique)
$processFilter = ($processIds | ForEach-Object { "ProcessId = $_" }) -join ' OR '
$processes = if ($processFilter) {
  @(Get-CimInstance Win32_Process -Filter $processFilter -ErrorAction SilentlyContinue | Select-Object ProcessId,Name,ExecutablePath,CommandLine)
} else {
  @()
}
$services = if ($processIds.Count -gt 0) {
  @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -in $processIds } | Select-Object Name,DisplayName,State,ProcessId)
} else {
  @()
}
[pscustomobject]@{
  tcp = $tcp
  udp = $udp
  processes = $processes
  services = $services
} | ConvertTo-Json -Depth 6 -Compress
`.trim();

const buildBinaryMetadataQuery = (executablePath) => `
$targetPath = '${executablePath.replace(/'/g, "''")}'
$item = Get-Item -LiteralPath $targetPath -ErrorAction Stop
$signature = Get-AuthenticodeSignature -LiteralPath $targetPath -ErrorAction SilentlyContinue
[pscustomobject]@{
  companyName = $item.VersionInfo.CompanyName
  fileDescription = $item.VersionInfo.FileDescription
  signatureStatus = if ($signature) { [string]$signature.Status } else { $null }
  signerSubject = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
} | ConvertTo-Json -Depth 4 -Compress
`.trim();

const normalizeAddress = (address) => {
  if (!address) {
    return '*';
  }

  const normalizedAddress = String(address).trim().toLowerCase();
  if (!normalizedAddress || normalizedAddress === '0.0.0.0' || normalizedAddress === '::' || normalizedAddress === '[::]') {
    return '*';
  }

  return normalizedAddress.startsWith('::ffff:')
    ? normalizedAddress.slice(7)
    : normalizedAddress;
};

const normalizeNumber = (value) => {
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
};

const normalizeText = (value) => {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmedValue = value.trim();
  return trimmedValue ? trimmedValue : null;
};

const buildExactKey = ({ protocol, localAddress, localPort, remoteAddress, remotePort }) =>
  `${protocol}|${normalizeAddress(localAddress)}|${localPort}|${normalizeAddress(remoteAddress)}|${remotePort}`;

const buildListenerKey = ({ protocol, localAddress, localPort }) =>
  `${protocol}|${normalizeAddress(localAddress)}|${localPort}`;

const buildLocalPortKey = ({ protocol, localPort }) => `${protocol}|${localPort}`;

const createEmptySnapshot = () => ({
  exactEndpoints: new Map(),
  listenerEndpoints: new Map(),
  localPortEndpoints: new Map(),
});

const executeProcessQuery = (command, script) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      child.kill();
      reject(new Error('Local process query timed out.'));
    }, PROCESS_QUERY_TIMEOUT_MS);

    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
    });

    child.on('error', error => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });

    child.on('close', code => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (code === 0) {
        resolve(stdout.trim());
        return;
      }

      reject(new Error(stderr.trim() || stdout.trim() || `Local process query exited with code ${code}.`));
    });
  });

const parseProcessQueryResponse = (payload) => {
  if (!payload) {
    return { tcp: [], udp: [], processes: [], services: [] };
  }

  const parsed = JSON.parse(payload);
  return {
    tcp: Array.isArray(parsed.tcp) ? parsed.tcp : parsed.tcp ? [parsed.tcp] : [],
    udp: Array.isArray(parsed.udp) ? parsed.udp : parsed.udp ? [parsed.udp] : [],
    processes: Array.isArray(parsed.processes) ? parsed.processes : parsed.processes ? [parsed.processes] : [],
    services: Array.isArray(parsed.services) ? parsed.services : parsed.services ? [parsed.services] : [],
  };
};

const buildProcessEntry = (endpoint, process, services, resolution) => ({
  pid: normalizeNumber(endpoint.OwningProcess ?? endpoint.owningProcess ?? process?.ProcessId ?? process?.pid),
  name: normalizeText(process?.Name ?? process?.name),
  executablePath: normalizeText(process?.ExecutablePath ?? process?.executablePath),
  commandLine: normalizeText(process?.CommandLine ?? process?.commandLine),
  companyName: null,
  fileDescription: null,
  signatureStatus: null,
  signerSubject: null,
  services,
  localAddress: endpoint.LocalAddress ?? endpoint.localAddress ?? null,
  localPort: normalizeNumber(endpoint.LocalPort ?? endpoint.localPort) ?? 0,
  remoteAddress: endpoint.RemoteAddress ?? endpoint.remoteAddress ?? null,
  remotePort: normalizeNumber(endpoint.RemotePort ?? endpoint.remotePort),
  protocol: endpoint.protocol,
  resolution,
});

const addIfMissing = (map, key, value) => {
  if (!map.has(key)) {
    map.set(key, value);
  }
};

const buildSnapshot = ({ tcp, udp, processes, services }) => {
  const snapshot = createEmptySnapshot();
  const processMap = new Map(
    processes.map(process => [normalizeNumber(process.ProcessId ?? process.pid), process])
      .filter(([processId]) => processId !== null)
  );
  const servicesByPid = new Map();

  for (const service of services) {
    const processId = normalizeNumber(service.ProcessId ?? service.processId);
    if (processId === null) {
      continue;
    }

    const existingServices = servicesByPid.get(processId) ?? [];
    existingServices.push({
      name: normalizeText(service.Name ?? service.name) ?? 'UnknownService',
      displayName: normalizeText(service.DisplayName ?? service.displayName),
      state: normalizeText(service.State ?? service.state),
    });
    servicesByPid.set(processId, existingServices);
  }

  for (const tcpEndpoint of tcp) {
    const localPort = normalizeNumber(tcpEndpoint.LocalPort ?? tcpEndpoint.localPort);
    const remotePort = normalizeNumber(tcpEndpoint.RemotePort ?? tcpEndpoint.remotePort);
    if (!localPort || remotePort === null) {
      continue;
    }

    const endpoint = {
      ...tcpEndpoint,
      protocol: 'TCP',
    };
    const processId = normalizeNumber(tcpEndpoint.OwningProcess ?? tcpEndpoint.owningProcess);
    const process = processMap.get(processId);
    const processServices = servicesByPid.get(processId) ?? [];

    addIfMissing(snapshot.exactEndpoints, buildExactKey({
      protocol: 'TCP',
      localAddress: tcpEndpoint.LocalAddress ?? tcpEndpoint.localAddress,
      localPort,
      remoteAddress: tcpEndpoint.RemoteAddress ?? tcpEndpoint.remoteAddress,
      remotePort,
    }), buildProcessEntry(endpoint, process, processServices, 'exact'));

    if (String(tcpEndpoint.State ?? tcpEndpoint.state).toLowerCase() === 'listen') {
      addIfMissing(snapshot.listenerEndpoints, buildListenerKey({
        protocol: 'TCP',
        localAddress: tcpEndpoint.LocalAddress ?? tcpEndpoint.localAddress,
        localPort,
      }), buildProcessEntry(endpoint, process, processServices, 'listener'));
    }

    addIfMissing(snapshot.localPortEndpoints, buildLocalPortKey({
      protocol: 'TCP',
      localPort,
    }), buildProcessEntry(endpoint, process, processServices, 'local_port'));
  }

  for (const udpEndpoint of udp) {
    const localPort = normalizeNumber(udpEndpoint.LocalPort ?? udpEndpoint.localPort);
    if (!localPort) {
      continue;
    }

    const endpoint = {
      ...udpEndpoint,
      protocol: 'UDP',
      RemoteAddress: null,
      RemotePort: null,
    };
    const processId = normalizeNumber(udpEndpoint.OwningProcess ?? udpEndpoint.owningProcess);
    const process = processMap.get(processId);
    const processServices = servicesByPid.get(processId) ?? [];

    addIfMissing(snapshot.listenerEndpoints, buildListenerKey({
      protocol: 'UDP',
      localAddress: udpEndpoint.LocalAddress ?? udpEndpoint.localAddress,
      localPort,
    }), buildProcessEntry(endpoint, process, processServices, 'listener'));

    addIfMissing(snapshot.localPortEndpoints, buildLocalPortKey({
      protocol: 'UDP',
      localPort,
    }), buildProcessEntry(endpoint, process, processServices, 'local_port'));
  }

  return snapshot;
};

const deriveLocalEndpointCandidates = (packet) => {
  const protocol = packet.protocol;
  if (protocol !== 'TCP' && protocol !== 'UDP') {
    return [];
  }

  if (packet.direction === 'OUTBOUND') {
    return [{
      protocol,
      localAddress: packet.sourceIp,
      localPort: packet.sourcePort,
      remoteAddress: packet.destinationIp,
      remotePort: packet.destinationPort,
    }];
  }

  if (packet.direction === 'INBOUND') {
    return [{
      protocol,
      localAddress: packet.destinationIp,
      localPort: packet.destinationPort,
      remoteAddress: packet.sourceIp,
      remotePort: packet.sourcePort,
    }];
  }

  return [
    {
      protocol,
      localAddress: packet.sourceIp,
      localPort: packet.sourcePort,
      remoteAddress: packet.destinationIp,
      remotePort: packet.destinationPort,
    },
    {
      protocol,
      localAddress: packet.destinationIp,
      localPort: packet.destinationPort,
      remoteAddress: packet.sourceIp,
      remotePort: packet.sourcePort,
    },
  ];
};

export class ProcessResolver {
  constructor({ refreshIntervalMs = DEFAULT_REFRESH_INTERVAL_MS, onError } = {}) {
    this.platform = os.platform();
    this.refreshIntervalMs = refreshIntervalMs;
    this.onError = onError;
    this.snapshot = createEmptySnapshot();
    this.lastRefreshAt = 0;
    this.refreshPromise = null;
    this.lastErrorAt = 0;
    this.binaryMetadataCache = new Map();
  }

  reportError(error) {
    if (!this.onError) {
      return;
    }

    const now = Date.now();
    if (now - this.lastErrorAt < ERROR_THROTTLE_MS) {
      return;
    }

    this.lastErrorAt = now;
    this.onError(error);
  }

  async refreshSnapshot() {
    if (this.platform !== 'win32') {
      return this.snapshot;
    }

    const payload = await executeProcessQuery('powershell.exe', WINDOWS_PROCESS_QUERY);
    this.snapshot = buildSnapshot(parseProcessQueryResponse(payload));
    this.lastRefreshAt = Date.now();
    return this.snapshot;
  }

  async getSnapshot() {
    if (this.platform !== 'win32') {
      return this.snapshot;
    }

    const now = Date.now();
    const hasSnapshot = this.lastRefreshAt > 0;
    const snapshotIsFresh = hasSnapshot && now - this.lastRefreshAt < this.refreshIntervalMs;

    if (snapshotIsFresh) {
      return this.snapshot;
    }

    if (this.refreshPromise) {
      return hasSnapshot ? this.snapshot : this.refreshPromise;
    }

    this.refreshPromise = this.refreshSnapshot()
      .catch(error => {
        this.reportError(error);
        return this.snapshot;
      })
      .finally(() => {
        this.refreshPromise = null;
      });

    return hasSnapshot ? this.snapshot : this.refreshPromise;
  }

  async getBinaryMetadata(executablePath) {
    if (this.platform !== 'win32' || !executablePath) {
      return null;
    }

    const cachedMetadata = this.binaryMetadataCache.get(executablePath);
    if (cachedMetadata && Date.now() - cachedMetadata.cachedAt < BINARY_METADATA_TTL_MS) {
      return cachedMetadata.value;
    }

    try {
      const payload = await executeProcessQuery('powershell.exe', buildBinaryMetadataQuery(executablePath));
      const parsed = payload ? JSON.parse(payload) : {};
      const metadata = {
        companyName: normalizeText(parsed.companyName),
        fileDescription: normalizeText(parsed.fileDescription),
        signatureStatus: normalizeText(parsed.signatureStatus),
        signerSubject: normalizeText(parsed.signerSubject),
      };
      this.binaryMetadataCache.set(executablePath, {
        cachedAt: Date.now(),
        value: metadata,
      });
      return metadata;
    } catch (error) {
      this.reportError(error);
      this.binaryMetadataCache.set(executablePath, {
        cachedAt: Date.now(),
        value: null,
      });
      return null;
    }
  }

  lookupPacket(packet, snapshot) {
    const candidates = deriveLocalEndpointCandidates(packet);

    for (const candidate of candidates) {
      if (candidate.protocol === 'TCP') {
        const exactMatch = snapshot.exactEndpoints.get(buildExactKey(candidate));
        if (exactMatch) {
          return exactMatch;
        }
      }

      const listenerMatch = snapshot.listenerEndpoints.get(buildListenerKey(candidate))
        ?? snapshot.listenerEndpoints.get(buildListenerKey({ ...candidate, localAddress: '*' }));
      if (listenerMatch) {
        return listenerMatch;
      }

      const localPortMatch = snapshot.localPortEndpoints.get(buildLocalPortKey(candidate));
      if (localPortMatch) {
        return localPortMatch;
      }
    }

    return null;
  }

  async enrichProcessEntry(entry) {
    if (!entry?.executablePath) {
      return entry;
    }

    const metadata = await this.getBinaryMetadata(entry.executablePath);
    if (!metadata) {
      return entry;
    }

    return {
      ...entry,
      ...metadata,
    };
  }

  async resolvePacket(packet) {
    if (this.platform !== 'win32') {
      return null;
    }

    try {
      const snapshot = await this.getSnapshot();
      const entry = this.lookupPacket(packet, snapshot);
      if (!entry) {
        return null;
      }
      return this.enrichProcessEntry(entry);
    } catch (error) {
      this.reportError(error);
      return null;
    }
  }
}

```

## File: `server/resetState.js`  
- Path: `server/resetState.js`  
- Size: 1228 Bytes  
- Modified: 2026-03-13 14:05:28 UTC

```javascript
import fs from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const dataDirectory = path.join(projectRoot, 'data');
const distDirectory = path.join(projectRoot, 'dist');

const removeIfExists = (targetPath) => {
  if (fs.existsSync(targetPath)) {
    fs.rmSync(targetPath, { recursive: true, force: true });
    return true;
  }
  return false;
};

const removedData = removeIfExists(dataDirectory);
const removedDist = removeIfExists(distDirectory);

fs.mkdirSync(dataDirectory, { recursive: true });

const { directories, getServerConfiguration } = await import('./db.js');
const config = getServerConfiguration();

console.log(JSON.stringify({
  ok: true,
  removedData,
  removedDist,
  recreated: {
    dataDirectory: directories.dataDirectory,
    pcapDirectory: directories.pcapDirectory,
    replayDirectory: directories.replayDirectory,
    databasePath: directories.databasePath,
  },
  config: {
    llmProvider: config.llmProvider,
    sensorId: config.sensorId,
    sensorName: config.sensorName,
    captureInterface: config.captureInterface,
    captureFilter: config.captureFilter,
    providerSettings: {
      lmstudio: config.providerSettings.lmstudio,
    },
  },
}, null, 2));

```

## File: `server/threatIntelService.js`  
- Path: `server/threatIntelService.js`  
- Size: 7128 Bytes  
- Modified: 2026-03-13 13:15:24 UTC

```javascript
import net from 'node:net';
import { listThreatIntelIndicators, replaceThreatIntelIndicators } from './db.js';

const normalizeIndicator = (value) => value.trim();

const matchesCidr = (ipAddress, cidrNotation) => {
  const [networkAddress, prefixLengthText] = cidrNotation.split('/');
  const prefixLength = Number(prefixLengthText);
  const family = net.isIP(networkAddress);
  if (!family || !net.isIP(ipAddress) || !Number.isInteger(prefixLength)) {
    return false;
  }

  const blockList = new net.BlockList();
  blockList.addSubnet(networkAddress, prefixLength, family === 6 ? 'ipv6' : 'ipv4');
  return blockList.check(ipAddress, family === 6 ? 'ipv6' : 'ipv4');
};

const parsePlainIndicators = (text) =>
  text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith(';'))
    .map(line => line.split(/[,\s;]/)[0]?.trim())
    .filter(Boolean)
    .map(indicator => ({
      indicator: normalizeIndicator(indicator),
      indicatorType: indicator.includes('/') ? 'cidr' : 'ip',
      label: 'plain_feed',
      confidence: 0.98,
    }));

const parseSpamhausDrop = (text) =>
  text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith(';') && !line.startsWith('#'))
    .map(line => {
      const [indicator, label] = line.split(';').map(part => part.trim());
      return {
        indicator: normalizeIndicator(indicator),
        indicatorType: indicator.includes('/') ? 'cidr' : 'ip',
        label: label || 'spamhaus_drop',
        confidence: 1,
      };
    })
    .filter(item => item.indicator);

const parseJsonArray = (text) => {
  const payload = JSON.parse(text);
  if (!Array.isArray(payload)) {
    return [];
  }

  return payload
    .map(item => {
      if (typeof item === 'string') {
        return {
          indicator: normalizeIndicator(item),
          indicatorType: item.includes('/') ? 'cidr' : 'ip',
          label: 'json_feed',
          confidence: 0.95,
        };
      }

      if (item && typeof item === 'object' && typeof item.indicator === 'string') {
        return {
          indicator: normalizeIndicator(item.indicator),
          indicatorType: item.indicator.includes('/') ? 'cidr' : 'ip',
          label: typeof item.label === 'string' ? item.label : 'json_feed',
          confidence: typeof item.confidence === 'number' ? item.confidence : 0.95,
          metadata: item,
        };
      }

      return null;
    })
    .filter(Boolean);
};

const parseSourceResponse = (source, text) => {
  switch (source.format) {
    case 'spamhaus_drop':
      return parseSpamhausDrop(text);
    case 'json_array':
      return parseJsonArray(text);
    case 'plain':
    default:
      return parsePlainIndicators(text);
  }
};

export class ThreatIntelService {
  constructor({ onStatusChange, onLog }) {
    this.onStatusChange = onStatusChange;
    this.onLog = onLog;
    this.status = {
      enabled: false,
      loadedIndicators: 0,
      sourceCount: 0,
      lastRefreshAt: null,
      lastError: null,
      refreshing: false,
    };
    this.refreshTimer = null;
    this.exactMatches = new Map();
    this.cidrMatches = [];
    this.loadIndicatorsFromDb();
  }

  loadIndicatorsFromDb() {
    const indicators = listThreatIntelIndicators();
    this.exactMatches.clear();
    this.cidrMatches = [];

    indicators.forEach(indicator => {
      if (indicator.indicatorType === 'cidr') {
        this.cidrMatches.push(indicator);
        return;
      }

      const existing = this.exactMatches.get(indicator.indicator) ?? [];
      existing.push(indicator);
      this.exactMatches.set(indicator.indicator, existing);
    });

    this.status.loadedIndicators = indicators.length;
  }

  getStatus() {
    return {
      ...this.status,
    };
  }

  stop() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  configure(config) {
    this.stop();
    this.status.enabled = config.threatIntelEnabled;
    this.status.sourceCount = config.threatIntelSources.length;
    this.onStatusChange(this.getStatus());

    if (!config.threatIntelEnabled) {
      return;
    }

    const intervalMs = Math.max(config.threatIntelRefreshHours, 1) * 60 * 60 * 1000;
    this.refreshTimer = setInterval(() => {
      void this.refresh(config);
    }, intervalMs);

    if (!this.status.lastRefreshAt) {
      void this.refresh(config);
    }
  }

  async refresh(config) {
    if (!config.threatIntelEnabled) {
      return this.getStatus();
    }

    const enabledSources = config.threatIntelSources.filter(source => source.enabled);
    const disabledSources = config.threatIntelSources.filter(source => !source.enabled);
    this.status = {
      ...this.status,
      enabled: true,
      sourceCount: config.threatIntelSources.length,
      refreshing: true,
      lastError: null,
    };
    this.onStatusChange(this.getStatus());

    try {
      for (const source of disabledSources) {
        replaceThreatIntelIndicators(source, []);
      }

      for (const source of enabledSources) {
        const response = await fetch(source.url);
        if (!response.ok) {
          throw new Error(`Threat intel source ${source.name} responded with ${response.status}.`);
        }

        const text = await response.text();
        const indicators = parseSourceResponse(source, text);
        replaceThreatIntelIndicators(source, indicators);
      }

      this.loadIndicatorsFromDb();
      this.status = {
        ...this.status,
        enabled: true,
        sourceCount: config.threatIntelSources.length,
        lastRefreshAt: new Date().toISOString(),
        lastError: null,
        refreshing: false,
      };
      this.onLog('INFO', 'Threat intelligence feeds refreshed.', {
        loadedIndicators: this.status.loadedIndicators,
        sources: enabledSources.length,
      });
    } catch (error) {
      this.status = {
        ...this.status,
        enabled: true,
        sourceCount: config.threatIntelSources.length,
        lastError: error instanceof Error ? error.message : 'Threat intelligence refresh failed.',
        refreshing: false,
      };
      this.onLog('ERROR', 'Threat intelligence refresh failed.', {
        error: this.status.lastError,
      });
    }

    this.onStatusChange(this.getStatus());
    return this.getStatus();
  }

  lookupIp(ipAddress) {
    const exactMatches = this.exactMatches.get(ipAddress);
    if (exactMatches && exactMatches.length > 0) {
      const [match] = exactMatches;
      return {
        indicator: match.indicator,
        sourceName: match.sourceName,
        label: match.label || 'threat_intel',
        confidence: match.confidence ?? 1,
      };
    }

    for (const indicator of this.cidrMatches) {
      if (matchesCidr(ipAddress, indicator.indicator)) {
        return {
          indicator: indicator.indicator,
          sourceName: indicator.sourceName,
          label: indicator.label || 'threat_intel',
          confidence: indicator.confidence ?? 1,
        };
      }
    }

    return null;
  }
}

```

## File: `server/webhookDispatcher.js`  
- Path: `server/webhookDispatcher.js`  
- Size: 2795 Bytes  
- Modified: 2026-03-13 11:38:46 UTC

```javascript
const formatMarkdownAlert = (event) =>
  [
    `Threat: ${event.attackType}`,
    `Action: ${event.action}`,
    `Source: ${event.sourceIp}:${event.sourcePort}`,
    `Destination: ${event.destinationIp}:${event.destinationPort}`,
    `Confidence: ${event.confidence.toFixed(2)}`,
    `Provider: ${event.provider}`,
    `Explanation: ${event.explanation}`,
  ].join('\n');

const buildPayload = (destination, event) => {
  switch (destination.provider) {
    case 'slack':
      return {
        text: formatMarkdownAlert(event),
      };
    case 'discord':
      return {
        content: formatMarkdownAlert(event),
      };
    case 'teams':
      return {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        summary: `NetGuard alert: ${event.attackType}`,
        themeColor: event.severity === 'critical' ? 'E81123' : 'FFB900',
        sections: [
          {
            activityTitle: `NetGuard alert: ${event.attackType}`,
            facts: [
              { name: 'Action', value: event.action },
              { name: 'Source', value: `${event.sourceIp}:${event.sourcePort}` },
              { name: 'Destination', value: `${event.destinationIp}:${event.destinationPort}` },
              { name: 'Confidence', value: event.confidence.toFixed(2) },
              { name: 'Provider', value: event.provider },
            ],
            text: event.explanation,
          },
        ],
      };
    default:
      return {
        event: 'netguard.alert',
        payload: event,
      };
  }
};

const sendWebhook = async (destination, event) => {
  const response = await fetch(destination.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'NetGuard-AI/1.0',
    },
    body: JSON.stringify(buildPayload(destination, event)),
  });

  if (!response.ok) {
    const responseText = await response.text();
    throw new Error(`${destination.name} responded with ${response.status}: ${responseText}`);
  }
};

export const dispatchAlertWebhooks = async (destinations, event) => {
  const enabledDestinations = destinations.filter(destination => destination.enabled && destination.url);
  const results = await Promise.allSettled(enabledDestinations.map(destination => sendWebhook(destination, event)));

  return {
    delivered: results.filter(result => result.status === 'fulfilled').length,
    failed: results.filter(result => result.status === 'rejected').length,
    results: results.map((result, index) => ({
      destination: enabledDestinations[index]?.name || `destination-${index + 1}`,
      success: result.status === 'fulfilled',
      error: result.status === 'rejected' ? result.reason instanceof Error ? result.reason.message : String(result.reason) : null,
    })),
  };
};

```

## File: `services/analysisCoordinator.ts`  
- Path: `services/analysisCoordinator.ts`  
- Size: 3848 Bytes  
- Modified: 2026-03-13 11:49:28 UTC

```typescript
import { LRUCache } from 'lru-cache';
import { AnalysisResult, Configuration, Packet } from '../types';
import { analyzeTrafficBatch } from './llmService';

interface CachedAnalysisResult {
  isSuspicious: boolean;
  attackType: AnalysisResult['attackType'];
  confidence: number;
  explanation: string;
  matchedSignals: string[];
}

interface PendingAnalysis {
  packet: Packet;
  config: Configuration;
  resolve: (result: AnalysisResult) => void;
  reject: (error: unknown) => void;
}

interface QueueState {
  items: PendingAnalysis[];
  timer: number | null;
}

export class AnalysisCoordinator {
  private cache: LRUCache<string, CachedAnalysisResult>;
  private queues: Map<string, QueueState>;

  constructor() {
    this.cache = new LRUCache<string, CachedAnalysisResult>({
      max: 5_000,
    });
    this.queues = new Map<string, QueueState>();
  }

  reset() {
    for (const queue of this.queues.values()) {
      if (queue.timer) {
        window.clearTimeout(queue.timer);
      }
      queue.items.forEach(item => item.reject(new Error('Analysis queue reset.')));
    }
    this.queues.clear();
    this.cache.clear();
  }

  async analyze(packet: Packet, config: Configuration): Promise<AnalysisResult> {
    const cacheKey = this.getCacheKey(packet);
    const cached = this.cache.get(cacheKey);

    if (cached) {
      return {
        ...cached,
        packet,
        decisionSource: 'cache',
      };
    }

    return new Promise((resolve, reject) => {
      const queueKey = this.getQueueKey(config);
      const queue = this.getOrCreateQueue(queueKey);
      queue.items.push({ packet, config, resolve, reject });

      if (queue.items.length >= config.batchMaxSize) {
        this.flushQueue(queueKey).catch(reject);
        return;
      }

      if (!queue.timer) {
        queue.timer = window.setTimeout(() => {
          this.flushQueue(queueKey).catch(error => {
            console.error('Failed to flush LLM batch queue:', error);
          });
        }, config.batchWindowMs);
      }
    });
  }

  getCacheKey(packet: Packet) {
    return `${packet.sourceIp}:${packet.destinationPort}:${packet.protocol}`;
  }

  getQueueKey(config: Configuration) {
    const providerSettings = config.providerSettings[config.llmProvider];
    return JSON.stringify({
      provider: config.llmProvider,
      model: providerSettings.model,
      baseUrl: providerSettings.baseUrl,
    });
  }

  getOrCreateQueue(queueKey: string) {
    const existing = this.queues.get(queueKey);
    if (existing) {
      return existing;
    }

    const queue: QueueState = {
      items: [],
      timer: null,
    };
    this.queues.set(queueKey, queue);
    return queue;
  }

  async flushQueue(queueKey: string) {
    const queue = this.queues.get(queueKey);
    if (!queue || queue.items.length === 0) {
      return;
    }

    if (queue.timer) {
      window.clearTimeout(queue.timer);
      queue.timer = null;
    }

    const items = [...queue.items];
    queue.items = [];

    const [firstItem] = items;
    if (!firstItem) {
      return;
    }

    try {
      const results = await analyzeTrafficBatch(
        items.map(item => item.packet),
        firstItem.config
      );

      results.forEach((result, index) => {
        const pendingItem = items[index];
        if (!pendingItem) {
          return;
        }

        this.cache.set(this.getCacheKey(pendingItem.packet), {
          isSuspicious: result.isSuspicious,
          attackType: result.attackType,
          confidence: result.confidence,
          explanation: result.explanation,
          matchedSignals: result.matchedSignals,
        }, {
          ttl: pendingItem.config.cacheTtlSeconds * 1000,
        });

        pendingItem.resolve(result);
      });
    } catch (error) {
      items.forEach(item => item.reject(error));
    }
  }
}

```

## File: `services/backendService.ts`  
- Path: `services/backendService.ts`  
- Size: 7011 Bytes  
- Modified: 2026-03-13 14:21:22 UTC

```typescript
import {
  BootstrapPayload,
  CaptureInterface,
  CaptureStatusPayload,
  Configuration,
  LogEntry,
  MetricSnapshot,
  PcapArtifact,
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

export const getArtifactDownloadUrl = (baseUrl: string, artifactId: string) =>
  `${normalizeBaseUrl(baseUrl)}/api/pcap-artifacts/${encodeURIComponent(artifactId)}/download`;

```

## File: `services/heuristicAnalyzer.ts`  
- Path: `services/heuristicAnalyzer.ts`  
- Size: 6001 Bytes  
- Modified: 2026-03-13 11:46:48 UTC

```typescript
import { AnalysisResult, AttackType, Configuration, Packet } from '../types';

const DDOS_WINDOW_MS = 5_000;
const DDOS_PACKET_THRESHOLD = 150;
const PORT_SCAN_WINDOW_MS = 15_000;
const PORT_SCAN_PORT_THRESHOLD = 12;
const BRUTE_FORCE_WINDOW_MS = 30_000;
const BRUTE_FORCE_ATTEMPTS = 16;

const AUTH_PORTS = new Set([21, 22, 23, 25, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432]);
const COMMON_BENIGN_PORTS = new Set([53, 80, 123, 443, 853]);
const MALICIOUS_KEYWORDS = [
  'powershell',
  'invoke-expression',
  'cmd.exe',
  '/bin/sh',
  'wget ',
  'curl ',
  'nc -e',
  'ncat ',
  'mimikatz',
  'union select',
  'drop table',
  '../',
  '<?php',
];

interface SourceWindowState {
  packetTimestamps: number[];
  authAttempts: number[];
  portTouches: Array<{ port: number; timestamp: number }>;
}

export interface HeuristicEvaluation {
  result: AnalysisResult | null;
  needsDeepInspection: boolean;
}

const decodeHexSnippet = (hexValue: string) => {
  try {
    const bytes = new Uint8Array(
      hexValue.match(/.{1,2}/g)?.map(byte => Number.parseInt(byte, 16)).filter(byte => !Number.isNaN(byte)) ?? []
    );
    return new TextDecoder().decode(bytes).toLowerCase();
  } catch {
    return '';
  }
};

const prune = (timestamps: number[], cutoff: number) => timestamps.filter(timestamp => timestamp >= cutoff);

const buildResult = (
  packet: Packet,
  overrides: Partial<Omit<AnalysisResult, 'packet' | 'decisionSource' | 'matchedSignals'>> & {
    decisionSource?: AnalysisResult['decisionSource'];
    matchedSignals?: string[];
  }
): AnalysisResult => ({
  isSuspicious: false,
  attackType: AttackType.NONE,
  confidence: 0.05,
  explanation: 'No heuristic anomaly detected.',
  packet,
  decisionSource: overrides.decisionSource ?? 'heuristic',
  matchedSignals: overrides.matchedSignals ?? [],
  ...overrides,
});

export class HeuristicAnalyzer {
  private sourceState: Map<string, SourceWindowState>;

  constructor() {
    this.sourceState = new Map<string, SourceWindowState>();
  }

  reset() {
    this.sourceState.clear();
  }

  evaluate(packet: Packet, config: Configuration): HeuristicEvaluation {
    const now = Date.parse(packet.timestamp) || Date.now();
    const state = this.getSourceState(packet.sourceIp);
    const payloadText = decodeHexSnippet(packet.payloadSnippet);

    state.packetTimestamps.push(now);
    state.authAttempts = prune(state.authAttempts, now - BRUTE_FORCE_WINDOW_MS);
    state.portTouches = state.portTouches.filter(entry => entry.timestamp >= now - PORT_SCAN_WINDOW_MS);
    state.packetTimestamps = prune(state.packetTimestamps, now - DDOS_WINDOW_MS);
    state.portTouches.push({ port: packet.destinationPort, timestamp: now });

    if (AUTH_PORTS.has(packet.destinationPort)) {
      state.authAttempts.push(now);
    }

    const uniqueTouchedPorts = new Set(state.portTouches.map(entry => entry.port));
    const matchedSignals: string[] = [];

    if (state.packetTimestamps.length >= DDOS_PACKET_THRESHOLD) {
      matchedSignals.push('rate.ddos.threshold');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.DDOS,
          confidence: 0.99,
          explanation: 'High packet rate from the same source indicates a volumetric attack.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    if (uniqueTouchedPorts.size >= PORT_SCAN_PORT_THRESHOLD) {
      matchedSignals.push('behavior.port_scan.multiple_ports');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.PORT_SCAN,
          confidence: 0.96,
          explanation: 'The same source probed many destination ports in a short time window.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    if (state.authAttempts.length >= BRUTE_FORCE_ATTEMPTS) {
      matchedSignals.push('behavior.brute_force.repeated_auth');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.BRUTE_FORCE,
          confidence: 0.94,
          explanation: 'Repeated authentication-oriented traffic suggests a brute-force attempt.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    if (payloadText && MALICIOUS_KEYWORDS.some(keyword => payloadText.includes(keyword))) {
      matchedSignals.push('payload.signature.known_malicious');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.MALICIOUS_PAYLOAD,
          confidence: 0.97,
          explanation: 'Known malicious command patterns were found in the packet payload.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    const touchesMonitoredPort = config.monitoringPorts.includes(packet.destinationPort);
    const targetsSensitivePort = AUTH_PORTS.has(packet.destinationPort) || touchesMonitoredPort;
    const containsPayload = packet.payloadSnippet.length > 0;
    const isCommonBenignPort = COMMON_BENIGN_PORTS.has(packet.destinationPort);

    if ((targetsSensitivePort && packet.direction === 'INBOUND') || (containsPayload && !isCommonBenignPort)) {
      matchedSignals.push('inspection.deep.required');
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    return {
      result: buildResult(packet, {
        confidence: 0.08,
        explanation: 'Traffic matched benign heuristic rules and did not require deep inspection.',
      }),
      needsDeepInspection: false,
    };
  }

  getSourceState(sourceIp: string): SourceWindowState {
    const existing = this.sourceState.get(sourceIp);
    if (existing) {
      return existing;
    }

    const nextState: SourceWindowState = {
      packetTimestamps: [],
      authAttempts: [],
      portTouches: [],
    };
    this.sourceState.set(sourceIp, nextState);
    return nextState;
  }
}

```

## File: `services/llmProviders.ts`  
- Path: `services/llmProviders.ts`  
- Size: 4649 Bytes  
- Modified: 2026-03-13 11:20:18 UTC

```typescript
import { Configuration, LlmProvider, LlmProviderSettings, ProviderTransport } from '../types';

declare const __LLM_ENV__: Record<string, string>;

export interface ProviderDefinition {
  id: LlmProvider;
  label: string;
  transport: ProviderTransport;
  defaultModel: string;
  defaultBaseUrl: string;
  envVar: string;
  requiresApiKey: boolean;
  local: boolean;
}

const LLM_ENV = typeof __LLM_ENV__ === 'undefined' ? {} : __LLM_ENV__;

export const PROVIDER_DEFINITIONS: ProviderDefinition[] = [
  {
    id: 'gemini',
    label: 'Gemini',
    transport: 'gemini',
    defaultModel: 'gemini-2.5-flash',
    defaultBaseUrl: 'https://generativelanguage.googleapis.com',
    envVar: 'GEMINI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'openai',
    label: 'OpenAI',
    transport: 'openai-compatible',
    defaultModel: 'gpt-4.1-mini',
    defaultBaseUrl: 'https://api.openai.com/v1',
    envVar: 'OPENAI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'anthropic',
    label: 'Anthropic',
    transport: 'anthropic',
    defaultModel: 'claude-3-5-sonnet-latest',
    defaultBaseUrl: 'https://api.anthropic.com',
    envVar: 'ANTHROPIC_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'openrouter',
    label: 'OpenRouter',
    transport: 'openai-compatible',
    defaultModel: 'openai/gpt-4.1-mini',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    envVar: 'OPENROUTER_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'groq',
    label: 'Groq',
    transport: 'openai-compatible',
    defaultModel: 'llama-3.3-70b-versatile',
    defaultBaseUrl: 'https://api.groq.com/openai/v1',
    envVar: 'GROQ_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'mistral',
    label: 'Mistral',
    transport: 'openai-compatible',
    defaultModel: 'mistral-small-latest',
    defaultBaseUrl: 'https://api.mistral.ai/v1',
    envVar: 'MISTRAL_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    transport: 'openai-compatible',
    defaultModel: 'deepseek-chat',
    defaultBaseUrl: 'https://api.deepseek.com',
    envVar: 'DEEPSEEK_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'xai',
    label: 'xAI',
    transport: 'openai-compatible',
    defaultModel: 'grok-2-latest',
    defaultBaseUrl: 'https://api.x.ai/v1',
    envVar: 'XAI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'lmstudio',
    label: 'LM Studio',
    transport: 'openai-compatible',
    defaultModel: 'local-model',
    defaultBaseUrl: 'http://localhost:1234/v1',
    envVar: '',
    requiresApiKey: false,
    local: true,
  },
  {
    id: 'ollama',
    label: 'Ollama',
    transport: 'ollama',
    defaultModel: 'llama3.2',
    defaultBaseUrl: 'http://localhost:11434',
    envVar: '',
    requiresApiKey: false,
    local: true,
  },
];

const providerMap = PROVIDER_DEFINITIONS.reduce<Record<LlmProvider, ProviderDefinition>>((accumulator, definition) => {
  accumulator[definition.id] = definition;
  return accumulator;
}, {} as Record<LlmProvider, ProviderDefinition>);

const getEnvApiKey = (envVar: string) => (envVar ? LLM_ENV[envVar] ?? '' : '');

export const getProviderDefinition = (provider: LlmProvider): ProviderDefinition => providerMap[provider];

export const createDefaultProviderSettings = (): Record<LlmProvider, LlmProviderSettings> =>
  PROVIDER_DEFINITIONS.reduce<Record<LlmProvider, LlmProviderSettings>>((accumulator, definition) => {
    accumulator[definition.id] = {
      model: definition.defaultModel,
      baseUrl: definition.defaultBaseUrl,
      apiKey: getEnvApiKey(definition.envVar),
    };
    return accumulator;
  }, {} as Record<LlmProvider, LlmProviderSettings>);

export const mergeProviderSettings = (
  savedSettings?: Partial<Record<LlmProvider, Partial<LlmProviderSettings>>>
): Record<LlmProvider, LlmProviderSettings> => {
  const defaults = createDefaultProviderSettings();

  if (!savedSettings) {
    return defaults;
  }

  return PROVIDER_DEFINITIONS.reduce<Record<LlmProvider, LlmProviderSettings>>((accumulator, definition) => {
    const savedProviderSettings = savedSettings[definition.id];
    accumulator[definition.id] = {
      ...defaults[definition.id],
      ...savedProviderSettings,
      apiKey: savedProviderSettings?.apiKey || defaults[definition.id].apiKey,
    };
    return accumulator;
  }, {} as Record<LlmProvider, LlmProviderSettings>);
};

export const getSelectedProviderSettings = (config: Configuration): LlmProviderSettings =>
  config.providerSettings[config.llmProvider];

```

## File: `services/llmService.ts`  
- Path: `services/llmService.ts`  
- Size: 12266 Bytes  
- Modified: 2026-03-13 11:47:28 UTC

```typescript
import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, AttackType, Configuration, Packet, ProviderTransport } from '../types';
import { getProviderDefinition, getSelectedProviderSettings } from './llmProviders';

const SYSTEM_PROMPT = `You are an expert network security analyst.
Return strictly valid raw JSON and nothing else.

Available attack types:
- port_scan
- brute_force
- malicious_payload
- ddos
- none
- other

Use "none" for benign traffic. Confidence must be a number between 0.0 and 1.0.
Explain the decision in one concise sentence.`;

const buildPacketProjection = (packet: Packet) => ({
  packet_id: packet.id,
  timestamp: packet.timestamp,
  direction: packet.direction,
  capture_device: packet.captureDevice,
  source_ip: packet.sourceIp,
  source_port: packet.sourcePort,
  destination_ip: packet.destinationIp,
  destination_port: packet.destinationPort,
  protocol: packet.protocol,
  size: packet.size,
  payload_snippet_hex: packet.payloadSnippet,
});

const buildSinglePacketPrompt = (packet: Packet) =>
  `Analyze this captured network packet and return one JSON object.

${JSON.stringify(buildPacketProjection(packet), null, 2)}`;

const buildBatchPrompt = (packets: Packet[]) =>
  `Analyze the following captured network packets and return one JSON array with one result per packet.
Each result must include:
- packet_id
- is_suspicious
- attack_type
- confidence
- explanation

Packets:
${JSON.stringify(packets.map(buildPacketProjection), null, 2)}`;

const analysisResultSchema = {
  type: Type.OBJECT,
  properties: {
    is_suspicious: { type: Type.BOOLEAN },
    attack_type: { type: Type.STRING, enum: Object.values(AttackType) },
    confidence: { type: Type.NUMBER },
    explanation: { type: Type.STRING },
  },
  required: ['is_suspicious', 'attack_type', 'confidence', 'explanation'],
};

const batchAnalysisResultSchema = {
  type: Type.ARRAY,
  items: {
    type: Type.OBJECT,
    properties: {
      packet_id: { type: Type.STRING },
      is_suspicious: { type: Type.BOOLEAN },
      attack_type: { type: Type.STRING, enum: Object.values(AttackType) },
      confidence: { type: Type.NUMBER },
      explanation: { type: Type.STRING },
    },
    required: ['packet_id', 'is_suspicious', 'attack_type', 'confidence', 'explanation'],
  },
};

const getDefaultBenignResult = (packet: Packet, explanation: string, decisionSource: AnalysisResult['decisionSource'] = 'llm'): AnalysisResult => ({
  isSuspicious: false,
  attackType: AttackType.NONE,
  confidence: 0.0,
  explanation,
  packet,
  decisionSource,
  matchedSignals: [],
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const clampConfidence = (value: unknown): number => {
  const numericValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numericValue)) {
    return 0.0;
  }
  return Math.min(1, Math.max(0, numericValue));
};

const normalizeAttackType = (value: unknown): AttackType => {
  if (typeof value !== 'string') {
    return AttackType.NONE;
  }

  const normalizedValue = value.toLowerCase();
  return Object.values(AttackType).includes(normalizedValue as AttackType)
    ? (normalizedValue as AttackType)
    : AttackType.NONE;
};

const parseJsonPayload = (content: string): unknown => {
  const trimmedContent = content.trim();

  try {
    return JSON.parse(trimmedContent);
  } catch {
    const arrayStart = trimmedContent.indexOf('[');
    const objectStart = trimmedContent.indexOf('{');
    const startIndex = arrayStart !== -1 && (objectStart === -1 || arrayStart < objectStart) ? arrayStart : objectStart;
    const endIndex = Math.max(trimmedContent.lastIndexOf(']'), trimmedContent.lastIndexOf('}'));

    if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
      throw new Error("Could not find valid JSON in the LLM response.");
    }

    return JSON.parse(trimmedContent.slice(startIndex, endIndex + 1));
  }
};

const normalizeAnalysisResult = (
  packet: Packet,
  payload: Record<string, unknown>,
  decisionSource: AnalysisResult['decisionSource'] = 'llm'
): AnalysisResult => ({
  isSuspicious: Boolean(payload.is_suspicious ?? payload.isSuspicious ?? false),
  attackType: normalizeAttackType(payload.attack_type ?? payload.attackType),
  confidence: clampConfidence(payload.confidence),
  explanation:
    typeof payload.explanation === 'string' && payload.explanation.trim()
      ? payload.explanation.trim()
      : 'Analysis incomplete.',
  packet,
  decisionSource,
  matchedSignals: [],
});

const normalizeBaseUrl = (baseUrl: string, transport: ProviderTransport): string => {
  const trimmedBaseUrl = baseUrl.trim().replace(/\/+$/, '');

  switch (transport) {
    case 'openai-compatible':
      return trimmedBaseUrl.replace(/\/chat\/completions$/i, '');
    case 'anthropic':
      return trimmedBaseUrl.replace(/\/v1\/messages$/i, '');
    case 'ollama':
      return trimmedBaseUrl.replace(/\/api\/chat$/i, '');
    default:
      return trimmedBaseUrl;
  }
};

const joinUrl = (baseUrl: string, path: string) => `${baseUrl.replace(/\/+$/, '')}${path}`;

const getResolvedProviderConfig = (config: Configuration) => {
  const definition = getProviderDefinition(config.llmProvider);
  const selectedSettings = getSelectedProviderSettings(config);

  return {
    definition,
    model: selectedSettings.model.trim() || definition.defaultModel,
    baseUrl: normalizeBaseUrl(selectedSettings.baseUrl || definition.defaultBaseUrl, definition.transport),
    apiKey: selectedSettings.apiKey.trim(),
  };
};

const ensureApiKey = (providerLabel: string, envVar: string, apiKey: string) => {
  if (apiKey) {
    return apiKey;
  }

  throw new Error(`${providerLabel} API key is not configured${envVar ? ` (expected ${envVar})` : ''}.`);
};

const requestFromGemini = async (
  model: string,
  apiKey: string,
  userPrompt: string,
  responseSchema: unknown
) => {
  const ai = new GoogleGenAI({ apiKey });
  const response = await ai.models.generateContent({
    model,
    contents: `${SYSTEM_PROMPT}\n\n${userPrompt}`,
    config: {
      responseMimeType: 'application/json',
      responseSchema,
      temperature: 0.1,
    },
  });

  return parseJsonPayload(response.text);
};

const requestFromOpenAiCompatible = async (
  model: string,
  baseUrl: string,
  apiKey: string,
  userPrompt: string,
  requiresApiKey: boolean
) => {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (requiresApiKey) {
    headers.Authorization = `Bearer ${ensureApiKey('OpenAI-compatible provider', '', apiKey)}`;
  } else if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }

  const response = await fetch(joinUrl(baseUrl, '/chat/completions'), {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Provider responded with ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const responseContent = data?.choices?.[0]?.message?.content;

  if (typeof responseContent !== 'string') {
    throw new Error('Provider returned an invalid response payload.');
  }

  return parseJsonPayload(responseContent);
};

const requestFromAnthropic = async (
  model: string,
  baseUrl: string,
  apiKey: string,
  userPrompt: string
) => {
  const response = await fetch(joinUrl(baseUrl, '/v1/messages'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ensureApiKey('Anthropic', 'ANTHROPIC_API_KEY', apiKey),
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: 'user',
          content: userPrompt,
        },
      ],
      max_tokens: 1200,
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Anthropic responded with ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const responseContent = Array.isArray(data?.content)
    ? data.content
        .filter((item: { type?: string; text?: string }) => item?.type === 'text' && typeof item.text === 'string')
        .map((item: { text: string }) => item.text)
        .join('\n')
    : '';

  if (!responseContent) {
    throw new Error('Anthropic returned an invalid response payload.');
  }

  return parseJsonPayload(responseContent);
};

const requestFromOllama = async (model: string, baseUrl: string, userPrompt: string) => {
  const response = await fetch(joinUrl(baseUrl, '/api/chat'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      stream: false,
      format: 'json',
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Ollama responded with ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const responseContent = data?.message?.content;

  if (typeof responseContent !== 'string') {
    throw new Error('Ollama returned an invalid response payload.');
  }

  return parseJsonPayload(responseContent);
};

const requestProviderJson = async (config: Configuration, userPrompt: string, responseSchema: unknown) => {
  const { definition, model, baseUrl, apiKey } = getResolvedProviderConfig(config);

  switch (definition.transport) {
    case 'gemini':
      return requestFromGemini(model, ensureApiKey(definition.label, definition.envVar, apiKey), userPrompt, responseSchema);
    case 'openai-compatible':
      return requestFromOpenAiCompatible(model, baseUrl, apiKey, userPrompt, definition.requiresApiKey);
    case 'anthropic':
      return requestFromAnthropic(model, baseUrl, apiKey, userPrompt);
    case 'ollama':
      return requestFromOllama(model, baseUrl, userPrompt);
    default:
      throw new Error(`Unsupported provider transport: ${definition.transport}`);
  }
};

export const analyzeTraffic = async (packet: Packet, config: Configuration): Promise<AnalysisResult> => {
  try {
    const payload = await requestProviderJson(config, buildSinglePacketPrompt(packet), analysisResultSchema);

    if (!isRecord(payload)) {
      throw new Error('Provider did not return a JSON object.');
    }

    return normalizeAnalysisResult(packet, payload);
  } catch (error) {
    console.error('LLM analysis failed:', error);
    return getDefaultBenignResult(packet, error instanceof Error ? error.message : 'LLM analysis failed.');
  }
};

export const analyzeTrafficBatch = async (packets: Packet[], config: Configuration): Promise<AnalysisResult[]> => {
  if (packets.length === 0) {
    return [];
  }

  if (packets.length === 1) {
    return [await analyzeTraffic(packets[0], config)];
  }

  try {
    const payload = await requestProviderJson(config, buildBatchPrompt(packets), batchAnalysisResultSchema);

    if (!Array.isArray(payload)) {
      throw new Error('Provider did not return a JSON array for batch analysis.');
    }

    const resultsByPacketId = new Map<string, Record<string, unknown>>();

    for (const item of payload) {
      if (isRecord(item) && typeof item.packet_id === 'string') {
        resultsByPacketId.set(item.packet_id, item);
      }
    }

    return packets.map(packet => {
      const result = resultsByPacketId.get(packet.id);
      return result
        ? normalizeAnalysisResult(packet, result)
        : getDefaultBenignResult(packet, 'Batch analysis returned no decision for this packet.');
    });
  } catch (error) {
    console.error('LLM batch analysis failed:', error);
    return Promise.all(
      packets.map(packet =>
        analyzeTraffic(packet, config).catch(innerError =>
          getDefaultBenignResult(packet, innerError instanceof Error ? innerError.message : 'LLM fallback failed.')
        )
      )
    );
  }
};

```

## File: `services/storageService.ts`  
- Path: `services/storageService.ts`  
- Size: 3062 Bytes  
- Modified: 2026-03-13 11:41:32 UTC

```typescript
import Dexie, { Table } from 'dexie';
import { ActionType, LogEntry, TrafficLogEntry, TrafficMetricPoint } from '../types';

interface StoredLogEntry extends LogEntry {}

interface StoredTrafficEntry extends TrafficLogEntry {
  packetTimestamp: string;
  sourceIp: string;
  destinationPort: number;
}

class NetGuardDatabase extends Dexie {
  logs!: Table<StoredLogEntry, string>;
  traffic!: Table<StoredTrafficEntry, string>;

  constructor() {
    super('NetGuardDB');
    this.version(1).stores({
      logs: 'id,timestamp,level',
      traffic: 'id,createdAt,packetTimestamp,sourceIp,destinationPort,attackType,actionType',
    });
  }
}

const db = new NetGuardDatabase();

const toStoredTrafficEntry = (entry: TrafficLogEntry): StoredTrafficEntry => ({
  ...entry,
  packetTimestamp: entry.packet.timestamp,
  sourceIp: entry.packet.sourceIp,
  destinationPort: entry.packet.destinationPort,
});

export const persistLogEntry = async (entry: LogEntry) => {
  await db.logs.put(entry);
};

export const persistTrafficEntry = async (entry: TrafficLogEntry) => {
  await db.traffic.put(toStoredTrafficEntry(entry));
};

export const loadRecentLogs = async (limit = 500): Promise<LogEntry[]> =>
  db.logs.orderBy('timestamp').reverse().limit(limit).toArray();

export const loadRecentTraffic = async (limit = 50): Promise<TrafficLogEntry[]> =>
  (await db.traffic.orderBy('createdAt').reverse().limit(limit).toArray()).map(({ packetTimestamp: _packetTimestamp, sourceIp: _sourceIp, destinationPort: _destinationPort, ...entry }) => entry);

export const loadTrafficMetrics = async (hours = 24, bucketMinutes = 15): Promise<TrafficMetricPoint[]> => {
  const sinceDate = new Date(Date.now() - hours * 60 * 60 * 1000);
  const bucketSizeMs = bucketMinutes * 60 * 1000;
  const buckets = new Map<number, TrafficMetricPoint>();

  const entries = await db.traffic.where('createdAt').aboveOrEqual(sinceDate.toISOString()).toArray();

  for (const entry of entries) {
    const timestamp = Date.parse(entry.createdAt);
    const bucketStart = Math.floor(timestamp / bucketSizeMs) * bucketSizeMs;
    const currentBucket = buckets.get(bucketStart) ?? {
      bucketStart: new Date(bucketStart).toISOString(),
      trafficCount: 0,
      threatCount: 0,
      blockedCount: 0,
    };

    currentBucket.trafficCount += 1;
    if (entry.isSuspicious) {
      currentBucket.threatCount += 1;
    }
    if (entry.actionType === ActionType.BLOCK) {
      currentBucket.blockedCount += 1;
    }

    buckets.set(bucketStart, currentBucket);
  }

  return [...buckets.values()].sort((left, right) => left.bucketStart.localeCompare(right.bucketStart));
};

export const loadTrafficCounters = async () => {
  const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const [packetsProcessed, recentEntries] = await Promise.all([
    db.traffic.count(),
    db.traffic.where('createdAt').aboveOrEqual(last24Hours).toArray(),
  ]);

  return {
    packetsProcessed,
    threatsDetected: recentEntries.filter(entry => entry.isSuspicious).length,
  };
};

```

## File: `tsconfig.json`  
- Path: `tsconfig.json`  
- Size: 676 Bytes  
- Modified: 2025-07-16 21:24:12 UTC

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "experimentalDecorators": true,
    "useDefineForClassFields": false,
    "module": "ESNext",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "skipLibCheck": true,

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "allowJs": true,
    "jsx": "react-jsx",

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true,

    "paths": {
      "@/*" :  ["./*"]
    }
  }
}

```

## File: `types.ts`  
- Path: `types.ts`  
- Size: 9699 Bytes  
- Modified: 2026-03-13 14:21:22 UTC

```typescript
export type TransportProtocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';

export type PacketDirection = 'INBOUND' | 'OUTBOUND' | 'UNKNOWN';

export type Layer7Protocol = 'HTTP' | 'DNS' | 'TLS' | 'SSH' | 'SMB' | 'RDP' | 'FTP' | 'SQL' | 'UNKNOWN';

export type DeploymentMode = 'standalone' | 'hub' | 'agent';

export type PayloadMaskingMode = 'strict' | 'raw_local_only';

export type ThreatIntelFeedFormat = 'plain' | 'spamhaus_drop' | 'json_array';

export type ProcessResolutionStrategy = 'exact' | 'listener' | 'local_port' | 'unresolved';
export type ProcessSignatureStatus = string;

export interface LocalServiceInfo {
  name: string;
  displayName: string | null;
  state: string | null;
}

export interface LocalProcessInfo {
  pid: number | null;
  name: string | null;
  executablePath: string | null;
  commandLine: string | null;
  companyName: string | null;
  fileDescription: string | null;
  signatureStatus: ProcessSignatureStatus | null;
  signerSubject: string | null;
  services: LocalServiceInfo[];
  localAddress: string | null;
  localPort: number;
  remoteAddress: string | null;
  remotePort: number | null;
  protocol: TransportProtocol;
  resolution: ProcessResolutionStrategy;
}

export interface Packet {
  id: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: TransportProtocol;
  payloadSnippet: string;
  timestamp: string;
  captureDevice: string;
  size: number;
  direction: PacketDirection;
  l7Protocol: Layer7Protocol;
  l7Metadata: Record<string, string>;
  localProcess?: LocalProcessInfo | null;
  sensorId?: string;
  sensorName?: string;
}

export enum AttackType {
  PORT_SCAN = 'port_scan',
  BRUTE_FORCE = 'brute_force',
  MALICIOUS_PAYLOAD = 'malicious_payload',
  DDOS = 'ddos',
  NONE = 'none',
  OTHER = 'other',
}

export enum ActionType {
  REDIRECT = 'REDIRECT',
  BLOCK = 'BLOCK',
  ALLOW = 'ALLOW',
}

export type AnalysisDecisionSource =
  | 'exempt'
  | 'blocklist'
  | 'heuristic'
  | 'custom_rule'
  | 'llm'
  | 'cache'
  | 'replay'
  | 'threat_intel'
  | 'fleet_sync';

export interface AnalysisResult {
  isSuspicious: boolean;
  attackType: AttackType;
  confidence: number;
  explanation: string;
  packet: Packet;
  decisionSource: AnalysisDecisionSource;
  matchedSignals: string[];
  recommendedActionType?: ActionType;
  recommendedTargetPort?: number;
}

export interface TrafficLogEntry extends AnalysisResult {
  id: string;
  action: string;
  actionType: ActionType;
  createdAt: string;
  firewallApplied: boolean;
  pcapArtifactId?: string | null;
  sensorId: string;
  sensorName: string;
}

export interface Action {
  type: ActionType;
  targetPort?: number;
  sourceIp: string;
  sourcePort?: number;
  originalDestPort: number;
  reason?: string;
}

export enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  CRITICAL = 'CRITICAL',
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  message: string;
  details?: Record<string, unknown>;
  sensorId?: string;
  sensorName?: string;
}

export type LlmProvider =
  | 'gemini'
  | 'openai'
  | 'anthropic'
  | 'openrouter'
  | 'groq'
  | 'mistral'
  | 'deepseek'
  | 'xai'
  | 'lmstudio'
  | 'ollama';

export type ProviderTransport = 'gemini' | 'openai-compatible' | 'anthropic' | 'ollama';

export interface LlmProviderSettings {
  model: string;
  baseUrl: string;
  apiKey: string;
}

export type WebhookProvider = 'generic' | 'slack' | 'discord' | 'teams';

export interface WebhookIntegration {
  id: string;
  name: string;
  provider: WebhookProvider;
  url: string;
  enabled: boolean;
}

export interface CaptureInterface {
  name: string;
  description: string;
  addresses: string[];
  loopback: boolean;
}

export interface CaptureStatusPayload {
  running: boolean;
  activeDevice: string | null;
  activeFilter: string;
  startedAt: string | null;
  clientCount: number;
  replayActive: boolean;
  sensorId?: string;
  sensorName?: string;
}

export interface MetricSnapshot {
  packetsProcessed: number;
  threatsDetected: number;
  blockedDecisions: number;
  lastUpdatedAt: string;
}

export interface TrafficMetricPoint {
  bucketStart: string;
  trafficCount: number;
  threatCount: number;
  blockedCount: number;
}

export interface ReplayStatusPayload {
  state: 'idle' | 'running' | 'completed' | 'failed';
  fileName: string | null;
  processedPackets: number;
  totalPackets: number;
  startedAt: string | null;
  completedAt: string | null;
  message: string | null;
}

export interface PcapArtifact {
  id: string;
  createdAt: string;
  fileName: string;
  attackType: AttackType;
  sourceIp: string;
  packetCount: number;
  explanation: string;
  bytes: number;
  sensorId: string;
  sensorName: string;
}

export type CustomRuleField =
  | 'sourceIp'
  | 'destinationIp'
  | 'sourcePort'
  | 'destinationPort'
  | 'protocol'
  | 'direction'
  | 'size'
  | 'l7Protocol'
  | 'payloadSnippet'
  | 'l7.host'
  | 'l7.path'
  | 'l7.userAgent'
  | 'l7.dnsQuery'
  | 'l7.sni'
  | 'l7.sshBanner'
  | 'l7.ftpCommand'
  | 'l7.rdpCookie'
  | 'l7.smbCommand'
  | 'l7.sqlOperation';

export type CustomRuleOperator =
  | 'equals'
  | 'not_equals'
  | 'greater_than'
  | 'less_than'
  | 'contains'
  | 'starts_with'
  | 'in_cidr'
  | 'not_in_cidr'
  | 'in_list'
  | 'not_in_list';

export interface CustomRuleCondition {
  id: string;
  field: CustomRuleField;
  operator: CustomRuleOperator;
  value: string;
}

export interface CustomRuleOutcome {
  actionType: ActionType;
  attackType: AttackType;
  confidence: number;
  explanation: string;
  targetPort?: number;
  needsDeepInspection: boolean;
}

export interface CustomRule {
  id: string;
  name: string;
  enabled: boolean;
  matchMode: 'all' | 'any';
  conditions: CustomRuleCondition[];
  outcome: CustomRuleOutcome;
}

export interface ThreatIntelSource {
  id: string;
  name: string;
  url: string;
  format: ThreatIntelFeedFormat;
  enabled: boolean;
}

export interface ThreatIntelStatus {
  enabled: boolean;
  loadedIndicators: number;
  sourceCount: number;
  lastRefreshAt: string | null;
  lastError: string | null;
  refreshing: boolean;
}

export interface FleetStatusPayload {
  deploymentMode: DeploymentMode;
  sensorId: string;
  sensorName: string;
  connectedToHub: boolean;
  connectedSensors: number;
  hubUrl: string | null;
  lastSyncAt: string | null;
  lastError: string | null;
}

export interface SensorSummary {
  id: string;
  name: string;
  mode: DeploymentMode;
  connected: boolean;
  hubUrl: string | null;
  lastSeenAt: string | null;
  captureRunning: boolean;
  packetsProcessed: number;
  threatsDetected: number;
  blockedDecisions: number;
  lastEventAt: string | null;
  local: boolean;
}

export interface ThreatHuntingResponse {
  id: string;
  question: string;
  sql: string;
  summary: string;
  rows: Record<string, unknown>[];
  generatedAt: string;
}

export interface Configuration {
  llmProvider: LlmProvider;
  providerSettings: Record<LlmProvider, LlmProviderSettings>;
  backendBaseUrl: string;
  deploymentMode: DeploymentMode;
  sensorId: string;
  sensorName: string;
  hubUrl: string;
  fleetSharedToken: string;
  globalBlockPropagationEnabled: boolean;
  captureInterface: string;
  captureFilter: string;
  cacheTtlSeconds: number;
  batchWindowMs: number;
  batchMaxSize: number;
  securePort: number;
  monitoringPorts: number[];
  detectionThreshold: number;
  autoBlockThreats: boolean;
  liveRawFeedEnabled: boolean;
  firewallIntegrationEnabled: boolean;
  pcapBufferSize: number;
  payloadMaskingMode: PayloadMaskingMode;
  threatIntelEnabled: boolean;
  threatIntelRefreshHours: number;
  threatIntelAutoBlock: boolean;
  threatIntelSources: ThreatIntelSource[];
  blockedIps: string[];
  blockedPorts: number[];
  exemptPorts: number[];
  webhookIntegrations: WebhookIntegration[];
  customRules: CustomRule[];
}

export type ServerConfiguration = Omit<Configuration, 'backendBaseUrl'>;

export interface BootstrapPayload {
  config: ServerConfiguration;
  interfaces: CaptureInterface[];
  captureStatus: CaptureStatusPayload;
  metrics: MetricSnapshot;
  metricSeries: TrafficMetricPoint[];
  traffic: TrafficLogEntry[];
  logs: LogEntry[];
  artifacts: PcapArtifact[];
  replayStatus: ReplayStatusPayload;
  fleetStatus: FleetStatusPayload;
  sensors: SensorSummary[];
  threatIntelStatus: ThreatIntelStatus;
}

export type BackendWsMessage =
  | {
      type: 'capture-status';
      payload: CaptureStatusPayload;
    }
  | {
      type: 'capture-error';
      payload: {
        message: string;
        code?: string;
      };
    }
  | {
      type: 'metrics-update';
      payload: MetricSnapshot;
    }
  | {
      type: 'traffic-event';
      payload: TrafficLogEntry;
    }
  | {
      type: 'threat-detected';
      payload: TrafficLogEntry;
    }
  | {
      type: 'log-entry';
      payload: LogEntry;
    }
  | {
      type: 'raw-packet';
      payload: Packet;
    }
  | {
      type: 'replay-status';
      payload: ReplayStatusPayload;
    }
  | {
      type: 'pcap-artifact';
      payload: PcapArtifact;
    }
  | {
      type: 'fleet-status';
      payload: FleetStatusPayload;
    }
  | {
      type: 'sensor-update';
      payload: SensorSummary;
    }
  | {
      type: 'threat-intel-status';
      payload: ThreatIntelStatus;
    };

export interface MonitoringStatus {
  backendReachable: boolean;
  websocketConnected: boolean;
  captureRunning: boolean;
  activeDevice: string | null;
  activeFilter: string;
  lastStartedAt: string | null;
  lastError: string | null;
  replayStatus: ReplayStatusPayload;
  fleetStatus: FleetStatusPayload;
  threatIntelStatus: ThreatIntelStatus;
}

```

## File: `USE.md`  
- Path: `USE.md`  
- Size: 10614 Bytes  
- Modified: 2026-03-13 14:08:38 UTC

```markdown
# NetGuard AI mit LM Studio nutzen

Diese Anleitung zeigt eine komplette Beispiel-Konfiguration, mit der du eine echte Ueberwachung mit einem lokalen LM-Studio-Modell einrichtest und startest.

## Ziel des Beispiels

Wir bauen eine lokale Ueberwachung mit:

- Frontend unter `http://localhost:5173`
- NetGuard-Backend unter `http://localhost:8081`
- LM Studio als lokaler LLM-Provider unter `http://localhost:1234/v1`
- echtem Netzwerk-Capture ueber Npcap/libpcap

Das Beispiel ist so ausgelegt, dass du zuerst sicher testen kannst, ohne sofort automatische Firewall-Blocks zu aktivieren.

Dabei nutzen wir die neuen erweiterten Funktionen bewusst konservativ:

- `Deployment Mode`: `standalone`
- `Payload Privacy Mode`: `Raw payload for local LLMs only`
- `Threat Intelligence`: zuerst `aus`
- `Global block propagation`: zuerst `aus`
- `Threat Hunting`: erst nach den ersten echten Traffic-Daten

## Voraussetzungen

Vor dem Start muss folgendes vorhanden sein:

1. `Node.js` ist installiert.
2. Unter Windows ist `Npcap` installiert, inklusive `WinPcap compatibility mode`.
3. LM Studio ist installiert.
4. In LM Studio ist ein Modell heruntergeladen.
5. Der lokale OpenAI-kompatible Server in LM Studio ist aktiv.

Hinweis:
NetGuard startet bewusst mit der LM-Studio-Standard-Modell-ID `local-model`.
Diese Default-ID bleibt so gesetzt. Wenn LM Studio bei dir eine andere Modell-ID anzeigt, kannst du sie spaeter in `Settings` manuell ersetzen.

## 1. LM Studio vorbereiten

1. Starte LM Studio.
2. Lade ein lokales Modell.
3. Oeffne in LM Studio den Bereich fuer den lokalen Server.
4. Starte den lokalen OpenAI-kompatiblen Server.
5. Pruefe die URL. Fuer dieses Beispiel verwenden wir:

```text
http://localhost:1234/v1
```

6. Pruefe die Modell-ID.

Standard in NetGuard:

```text
local-model
```

Wenn LM Studio bei dir exakt `local-model` bereitstellt, musst du nichts aendern.
Wenn LM Studio eine andere Modell-ID liefert, uebernimm exakt diesen Wert spaeter in `Settings`.

Hinweis:
NetGuard erwartet bei LM Studio keine API-Keys. Wichtig sind nur `Base URL` und `Model ID`.

## 2. NetGuard starten

Im Projektordner:

```powershell
npm install
npm run dev
```

Danach:

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8081`

## 3. Beispiel-Konfiguration in NetGuard

Oeffne `http://localhost:5173` und gehe in den Tab `Settings`.

Verwende fuer den ersten echten Test diese Werte.

### Sensor & Backend

- `Deployment Mode`: `standalone`
- `Sensor ID`: `desktop-lab-01`
- `Sensor Name`: `Windows Lab Sensor`
- `Hub URL`: leer
- `Shared Fleet Token`: leer
- `Global block propagation`: `aus`
- `Backend Base URL`: `http://localhost:8081`
- `Capture Interface`: dein echtes Netzwerk-Interface
- `Capture Filter`: `ip and (tcp or udp)`
- `Live raw feed`: `aus` fuer den ersten Test

Wichtig:
Waehle nicht blind irgendein Interface. Nimm das Interface, ueber das dein Rechner wirklich online ist, zum Beispiel WLAN oder Ethernet.

Wenn du unsicher bist:

1. Klicke `Refresh Interfaces`
2. Suche das Interface mit deiner lokalen IP
3. Waehle dieses Interface aus

### LLM Configuration

- `LLM Provider`: `LM Studio`
- `Model ID`: `local-model`
- `Base URL`: `http://localhost:1234/v1`
- `Payload Privacy Mode`: `Raw payload for local LLMs only`

Wenn deine Modell-ID in LM Studio anders heisst, trage exakt diesen Namen ein.
Die Startkonfiguration von NetGuard bleibt trotzdem absichtlich `local-model`.

Warum genau diese Einstellung?

- `LM Studio` ist lokal, deshalb darf die rohe Payload auf deinem Rechner bleiben.
- Mit `Raw payload for local LLMs only` wird nichts fuer Cloud-Provider freigegeben.
- Falls du spaeter auf OpenAI, Anthropic oder einen anderen Cloud-Provider wechselst, stelle auf `Strict masking` um.

### Threat Intelligence

Fuer den ersten Test:

- `Enable threat intelligence`: `aus`
- `Auto-block threat intel matches`: `aus`
- `Refresh Interval (hours)`: `24`

So pruefst du zuerst sauber Capture, L7-Decoding und LM-Studio-Analyse ohne vorgeschaltete Feed-Entscheidungen.

### Analysis Pipeline

Empfohlene Startwerte:

- `Cache TTL (seconds)`: `60`
- `Batch Window (ms)`: `2000`
- `Batch Size`: `20`
- `Secure Redirect Port`: `9999`
- `PCAP Buffer Size`: `10`
- `Monitoring Ports`: `22, 80, 443, 8080, 3389`
- `Detection Threshold`: `0.75`
- `Auto-block detected threats`: `aus`
- `Enable OS firewall integration`: `aus`

Warum diese Werte?

- `Auto-block` ist fuer den Ersttest deaktiviert, damit du keine echte Verbindung versehentlich sperrst.
- `Firewall integration` bleibt zunaechst aus, bis die Erkennung sauber geprueft ist.

### Integrations

Fuer den ersten Test:

- keine Webhooks notwendig

### Blocklists / Exempt Ports

Fuer den ersten Test:

- `Blocked IPs`: leer
- `Blocked Ports`: leer
- `Exempt Ports`: leer

## 4. Beispiel fuer eine komplette Test-Konfiguration

Wenn alles korrekt gesetzt ist, sieht dein praktisches Beispiel so aus:

```text
Backend Base URL:        http://localhost:8081
Capture Interface:       Dein WLAN- oder Ethernet-Adapter
Capture Filter:          ip and (tcp or udp)

LLM Provider:            LM Studio
Model ID:                local-model
Base URL:                http://localhost:1234/v1

Cache TTL:               60
Batch Window:            2000
Batch Size:              20
Secure Redirect Port:    9999
PCAP Buffer Size:        10
Monitoring Ports:        22, 80, 443, 8080, 3389
Detection Threshold:     0.75
Auto-block:              aus
Firewall integration:    aus
Live raw feed:           aus
Deployment Mode:         standalone
Sensor ID:               desktop-lab-01
Sensor Name:             Windows Lab Sensor
Payload Privacy Mode:    Raw payload for local LLMs only
Threat Intelligence:     aus
Fleet Propagation:       aus
```

## 5. Ueberwachung starten

Wechsle jetzt in den Tab `Dashboard`.

Dort:

1. Pruefe, ob `Backend Sensor` auf `Connected` steht.
2. Pruefe, ob beim LLM-Status dein LM-Studio-Modell angezeigt wird.
3. Klicke auf `Start Monitoring`.

Wenn alles korrekt ist:

- `Monitoring Status` wechselt auf `Active`
- das Capture-Interface wird angezeigt
- die Metriken beginnen zu steigen
- bei Verkehr erscheinen Eintraege im `Analyzed Traffic Feed`

In diesem Beispiel bleibt der Sensor absichtlich `standalone`. Den Fleet-Modus richtest du erst ein, wenn der Einzelknoten stabil laeuft.

## 6. Funktion testen

Erzeuge jetzt echten Traffic auf deinem Rechner, zum Beispiel:

1. Oeffne einige Webseiten
2. Fuehre einen `ping` aus
3. Starte einen Download
4. Rufe lokal einen Dienst auf, falls vorhanden

Beispiel:

```powershell
ping 8.8.8.8
```

oder im Browser:

- `https://example.com`
- `https://openai.com`

Danach solltest du im Dashboard neue Daten sehen.

Wenn du dabei Verkehr auf typischen Ports erzeugst, siehst du jetzt oft auch neue Layer-7-Metadaten im Backend, zum Beispiel fuer:

- `HTTP`
- `TLS`
- `SSH`
- `RDP`
- `SMB`
- `SQL`

## 7. Woran du erkennst, dass es funktioniert

Eine funktionierende Ueberwachung erkennst du an diesen Punkten:

1. `Packets Processed` steigt an
2. Im `Analyzed Traffic Feed` erscheinen neue Zeilen
3. Im Diagramm `Traffic vs. Threats` entstehen Werte
4. Im Tab `Logs` erscheinen Backend- und Analyse-Ereignisse

## 8. Threat Hunting mit LM Studio testen

Sobald einige Pakete gespeichert wurden, kannst du die neue Forensik-Funktion pruefen:

1. Oeffne den Tab `Threat Hunt`
2. Lass `All Sensors` aktiv, weil wir in diesem Beispiel nur einen Sensor haben
3. Stelle eine Frage wie:

```text
Zeige mir alle Quell-IPs der letzten 24 Stunden, die Port 22 angesprochen haben und als brute_force oder port_scan bewertet wurden.
```

4. Klicke `Run Hunt`

Das Backend fuehrt dann real aus:

- Text-zu-SQL ueber dein konfiguriertes LM-Studio-Modell
- schreibgeschuetzte SQL-Ausfuehrung auf SQLite
- Rueckgabe von Zusammenfassung, SQL und Ergebniszeilen

## 9. Wenn beim Start nichts passiert

Pruefe in dieser Reihenfolge:

1. Laeuft LM Studio wirklich und ist der Server gestartet?
2. Stimmt die `Base URL` genau: `http://localhost:1234/v1`?
3. Stimmt die `Model ID` exakt mit LM Studio ueberein?
4. Ist das richtige `Capture Interface` ausgewaehlt?
5. Ist `Npcap` korrekt installiert?
6. Zeigt `Backend Sensor` im Dashboard `Connected`?
7. Ist der `Capture Filter` zu streng? Testweise:

```text
ip
```

statt:

```text
ip and (tcp or udp)
```

## 10. Empfohlener naechster Schritt nach dem Ersttest

Wenn die Ueberwachung stabil laeuft, kannst du schrittweise erweitern:

1. `Live raw feed` aktivieren, wenn du Layer-7-Metadaten sehen willst
2. Webhooks konfigurieren
3. Custom Rules im Tab `Rules` bauen
4. Erst danach `Auto-block` aktivieren
5. Ganz zuletzt `OS firewall integration` aktivieren

## 11. Threat Intelligence spaeter aktivieren

Wenn der Grundbetrieb stabil laeuft, kannst du die neuen TI-Feeds aktivieren:

Empfohlene Startwerte:

- `Enable threat intelligence`: `an`
- `Auto-block threat intel matches`: `an`
- `Refresh Interval (hours)`: `24`

Dann:

1. Gehe zu `Settings -> Threat Intelligence`
2. Klicke `Refresh Feeds`
3. Pruefe, ob `indicators loaded` groesser als `0` ist

Damit blockt NetGuard bekannte boesartige IPs bereits vor Heuristik und vor LLM-Analyse.

## 12. Fleet-Modus spaeter erweitern

Wenn du weitere Sensoren anbinden willst, nutze diese Grundaufteilung:

### Hub-Beispiel

- `Deployment Mode`: `hub`
- `Sensor ID`: `hq-hub-01`
- `Sensor Name`: `Central Hub`
- `Shared Fleet Token`: eigener geheimer Wert

### Agent-Beispiel

- `Deployment Mode`: `agent`
- `Sensor ID`: `branch-01`
- `Sensor Name`: `Branch Office Sensor`
- `Hub URL`: `http://IP-DES-HUBS:8080`
- `Shared Fleet Token`: derselbe Wert wie auf dem Hub
- `Global block propagation`: `an`

Dann gilt:

- der Agent analysiert lokal weiter
- Events werden an den Hub gespiegelt
- Block-Entscheidungen koennen global propagiert werden

## 13. Sichere Produktiv-Empfehlung fuer LM Studio

Fuer den produktiven Betrieb mit einem lokalen Modell:

- zuerst ohne Firewall-Automation testen
- Detection Threshold nicht zu niedrig setzen
- Custom Rules fuer bekannte interne Ausnahmen definieren
- PCAP-Exports aktiv nutzen, wenn Bedrohungen erkannt werden
- nur dann echtes Blocking aktivieren, wenn die Erkennung verifiziert ist

## Kurzfassung

Wenn du nur die Minimalversion willst:

1. LM Studio starten
2. Modell laden
3. LM-Studio-Server starten
4. `npm run dev`
5. In NetGuard:
   - Backend: `http://localhost:8081`
   - Provider: `LM Studio`
   - Modell: `local-model`
   - Base URL: `http://localhost:1234/v1`
   - richtiges Netzwerk-Interface waehlen
6. `Start Monitoring`

Dann laeuft die Ueberwachung mit echtem Capture und lokalem LLM.

```

## File: `utils.ts`  
- Path: `utils.ts`  
- Size: 2862 Bytes  
- Modified: 2026-03-13 14:08:38 UTC

```typescript
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

```

## File: `vite-env.d.ts`  
- Path: `vite-env.d.ts`  
- Size: 90 Bytes  
- Modified: 2026-03-13 11:20:18 UTC

```typescript
/// <reference types="vite/client" />

declare const __LLM_ENV__: Record<string, string>;

```

## File: `vite.config.ts`  
- Path: `vite.config.ts`  
- Size: 1359 Bytes  
- Modified: 2026-03-13 11:48:52 UTC

```typescript
import path from 'path';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const llmEnv = {
    GEMINI_API_KEY: env.GEMINI_API_KEY || env.VITE_GEMINI_API_KEY || '',
    OPENAI_API_KEY: env.OPENAI_API_KEY || env.VITE_OPENAI_API_KEY || '',
    ANTHROPIC_API_KEY: env.ANTHROPIC_API_KEY || env.VITE_ANTHROPIC_API_KEY || '',
    OPENROUTER_API_KEY: env.OPENROUTER_API_KEY || env.VITE_OPENROUTER_API_KEY || '',
    GROQ_API_KEY: env.GROQ_API_KEY || env.VITE_GROQ_API_KEY || '',
    MISTRAL_API_KEY: env.MISTRAL_API_KEY || env.VITE_MISTRAL_API_KEY || '',
    DEEPSEEK_API_KEY: env.DEEPSEEK_API_KEY || env.VITE_DEEPSEEK_API_KEY || '',
    XAI_API_KEY: env.XAI_API_KEY || env.VITE_XAI_API_KEY || '',
  };

  return {
    define: {
      __LLM_ENV__: JSON.stringify(llmEnv),
      'process.env.API_KEY': JSON.stringify(llmEnv.GEMINI_API_KEY),
      'process.env.GEMINI_API_KEY': JSON.stringify(llmEnv.GEMINI_API_KEY),
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            react: ['react', 'react-dom'],
            charts: ['recharts'],
            llm: ['@google/genai'],
            storage: ['dexie'],
          },
        },
      },
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
  };
});

```

