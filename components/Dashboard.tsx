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
  SandboxAnalysisSummary,
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
  onAnalyzeProcessInSandbox: (targetPath: string, options?: { processName?: string | null; trafficEventId?: string | null }) => Promise<SandboxAnalysisSummary | void>;
  monitoringStatus: MonitoringStatus;
  llmStatus: { loaded: boolean; model: string };
  metricsSnapshot: MetricSnapshot;
  liveTrafficFeed: TrafficLogEntry[];
  rawPacketFeed: Packet[];
  trafficMetrics: TrafficMetricPoint[];
  artifacts: PcapArtifact[];
  sandboxAnalyses: SandboxAnalysisSummary[];
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

const getSandboxVerdictClass = (verdict: SandboxAnalysisSummary['verdict']) => {
  switch (verdict) {
    case 'malicious':
      return 'text-red-300';
    case 'suspicious':
      return 'text-orange-300';
    case 'clean':
      return 'text-emerald-300';
    default:
      return 'text-gray-300';
  }
};

const getSandboxStatusClass = (status: SandboxAnalysisSummary['status']) => {
  switch (status) {
    case 'completed':
      return 'border-emerald-500/30 bg-emerald-500/15 text-emerald-100';
    case 'failed':
      return 'border-red-500/30 bg-red-500/15 text-red-100';
    case 'running':
      return 'border-blue-500/30 bg-blue-500/15 text-blue-100';
    default:
      return 'border-gray-600/50 bg-gray-700/50 text-gray-300';
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
  onSandboxAnalyze: (targetPath: string, options?: { processName?: string | null; trafficEventId?: string | null }) => Promise<void>;
  latestSandboxAnalysis: SandboxAnalysisSummary | null;
  sandboxActionPending: boolean;
}> = ({
  entry,
  getArtifactDownloadUrl,
  onFilterByProcess,
  onCopyProcessPath,
  onRevealProcessPath,
  onSandboxAnalyze,
  latestSandboxAnalysis,
  sandboxActionPending,
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
            {latestSandboxAnalysis && (
              <div className="mt-1 text-[11px] text-gray-400">
                <span className="font-semibold text-gray-300">{t('sandboxStatusLabel')}:</span>{' '}
                <span className={getSandboxVerdictClass(latestSandboxAnalysis.verdict)}>
                  {t(`sandboxVerdict_${latestSandboxAnalysis.verdict}`)}
                </span>
                {' • '}
                {t(`sandboxStatus_${latestSandboxAnalysis.status}`)}
                {latestSandboxAnalysis.score !== null ? ` • ${latestSandboxAnalysis.score.toFixed(1)}` : ''}
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
                  <button
                    type="button"
                    onClick={() => void onSandboxAnalyze(localProcess.executablePath!, {
                      processName: localProcess.name,
                      trafficEventId: entry.id,
                    })}
                    disabled={sandboxActionPending}
                    className="rounded-md border border-gray-600 px-2 py-1 text-[11px] font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {sandboxActionPending ? t('sandboxAnalyzeRunning') : t('sandboxAnalyzeButton')}
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
  onAnalyzeProcessInSandbox,
  monitoringStatus,
  llmStatus,
  metricsSnapshot,
  liveTrafficFeed,
  rawPacketFeed,
  trafficMetrics,
  artifacts,
  sandboxAnalyses,
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
  const [sandboxActionPath, setSandboxActionPath] = useState<string | null>(null);

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
  const latestSandboxAnalysesByPath = useMemo(() => {
    const analysisMap = new Map<string, SandboxAnalysisSummary>();
    sandboxAnalyses.forEach(analysis => {
      if (!analysisMap.has(analysis.filePath)) {
        analysisMap.set(analysis.filePath, analysis);
      }
    });
    return analysisMap;
  }, [sandboxAnalyses]);

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

  const handleSandboxAnalyze = async (targetPath: string, options?: { processName?: string | null; trafficEventId?: string | null }) => {
    try {
      setSandboxActionPath(targetPath);
      await onAnalyzeProcessInSandbox(targetPath, options);
      setProcessActionState({
        tone: 'success',
        message: t('sandboxAnalyzeQueued'),
      });
    } catch {
      setProcessActionState({
        tone: 'error',
        message: t('sandboxAnalyzeFailed'),
      });
    } finally {
      setSandboxActionPath(currentPath => (currentPath === targetPath ? null : currentPath));
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

      <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-5 shadow-xl">
        <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">{t('sandboxTitle')}</h2>
            <p className="text-sm text-gray-400">{t('sandboxDescription')}</p>
          </div>
          <div className="text-sm text-gray-400">{sandboxAnalyses.length.toLocaleString()} {t('sandboxRecentAnalyses')}</div>
        </div>

        <div className="mt-5 space-y-3">
          {sandboxAnalyses.length === 0 && (
            <div className="rounded-xl border border-dashed border-gray-700 p-6 text-center text-sm text-gray-500">
              {t('sandboxNoAnalyses')}
            </div>
          )}

          {sandboxAnalyses.map(analysis => (
            <div key={analysis.id} className="rounded-xl border border-gray-700 bg-gray-900/40 p-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <div className="text-sm font-semibold text-white">{analysis.fileName}</div>
                  <div className="mt-1 text-xs text-gray-400">
                    {formatLocaleTimestamp(analysis.updatedAt, t('localeCode'))} • {analysis.sensorName} • {analysis.provider.toUpperCase()} • {formatBytes(analysis.fileSize)}
                  </div>
                  <div className={`mt-2 text-sm font-semibold ${getSandboxVerdictClass(analysis.verdict)}`}>
                    {t(`sandboxVerdict_${analysis.verdict}`)}
                    {analysis.score !== null ? ` • ${analysis.score.toFixed(1)}` : ''}
                  </div>
                  <div className="mt-2 text-sm text-gray-400">{analysis.summary}</div>
                  {analysis.signatures.length > 0 && (
                    <div className="mt-2 text-xs text-gray-500">
                      {t('sandboxSignatures')}: {analysis.signatures.slice(0, 5).join(', ')}
                    </div>
                  )}
                  {analysis.errorMessage && (
                    <div className="mt-2 text-xs text-red-300">{analysis.errorMessage}</div>
                  )}
                </div>
                <div className="flex flex-col gap-2">
                  <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${getSandboxStatusClass(analysis.status)}`}>
                    {t(`sandboxStatus_${analysis.status}`)}
                  </span>
                  <button
                    type="button"
                    onClick={() => void handleCopyProcessPath(analysis.filePath)}
                    className="rounded-lg border border-gray-600 px-3 py-2 text-sm font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white"
                  >
                    {t('processCopyPath')}
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleRevealProcessPath(analysis.filePath)}
                    className="rounded-lg border border-gray-600 px-3 py-2 text-sm font-semibold text-gray-200 transition hover:border-blue-500 hover:text-white"
                  >
                    {t('processOpenFolder')}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

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
                    onSandboxAnalyze={handleSandboxAnalyze}
                    latestSandboxAnalysis={entry.packet.localProcess?.executablePath ? latestSandboxAnalysesByPath.get(entry.packet.localProcess.executablePath) ?? null : null}
                    sandboxActionPending={entry.packet.localProcess?.executablePath === sandboxActionPath}
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
