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
  onApplySettingsNow: () => Promise<void>;
  applySettingsPending: boolean;
  backendAppliedProviderLabel: string;
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
  onApplySettingsNow,
  applySettingsPending,
  backendAppliedProviderLabel,
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
          <p className="mt-2 text-sm text-blue-200">
            {t('settingsAppliedProviderLabel')}: <span className="font-semibold text-white">{backendAppliedProviderLabel}</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => void onApplySettingsNow()}
            disabled={applySettingsPending}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-700"
          >
            {applySettingsPending ? t('settingsApplyNowPending') : t('settingsApplyNow')}
          </button>
          <SyncBadge state={configSyncState} label={syncStateLabel} />
        </div>
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
            <TextInput
              label={t('localLlmTimeoutSeconds')}
              type="number"
              value={config.localLlmTimeoutSeconds}
              onChange={event => setConfig(previousConfig => ({
                ...previousConfig,
                localLlmTimeoutSeconds: Number.parseInt(event.target.value, 10) || 300,
              }))}
            />
            <p className="text-xs text-gray-500">{t('localLlmTimeoutHint')}</p>
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

        <SectionCard title={t('settingsSandbox')} description={t('settingsSandboxDescription')}>
          <div className="space-y-4">
            <ToggleField
              label={t('sandboxEnabled')}
              description={t('sandboxEnabledHint')}
              checked={config.sandboxEnabled}
              onChange={checked => setConfig(previousConfig => ({ ...previousConfig, sandboxEnabled: checked }))}
            />
            <ToggleField
              label={t('sandboxAutoSubmitSuspicious')}
              description={t('sandboxAutoSubmitSuspiciousHint')}
              checked={config.sandboxAutoSubmitSuspicious}
              onChange={checked => setConfig(previousConfig => ({ ...previousConfig, sandboxAutoSubmitSuspicious: checked }))}
            />
            <ToggleField
              label={t('sandboxPrioritizeLlmWorkloads')}
              description={t('sandboxPrioritizeLlmWorkloadsHint')}
              checked={config.sandboxPrioritizeLlmWorkloads}
              onChange={checked => setConfig(previousConfig => ({ ...previousConfig, sandboxPrioritizeLlmWorkloads: checked }))}
            />
            <SelectInput
              label={t('sandboxProvider')}
              value={config.sandboxProvider}
              onChange={event => setConfig(previousConfig => ({ ...previousConfig, sandboxProvider: event.target.value as Configuration['sandboxProvider'] }))}
            >
              <option value="cerberus_lab">{t('sandboxProvider_cerberus_lab')}</option>
              <option value="cape">{t('sandboxProvider_cape')}</option>
              <option value="none">{t('sandboxProvider_none')}</option>
            </SelectInput>
            {config.sandboxProvider === 'cape' ? (
              <>
                <TextInput
                  label={t('sandboxBaseUrl')}
                  value={config.sandboxBaseUrl}
                  onChange={event => setConfig(previousConfig => ({ ...previousConfig, sandboxBaseUrl: event.target.value }))}
                  placeholder="http://localhost:8090"
                />
                <TextInput
                  label={t('sandboxApiKey')}
                  type="password"
                  value={config.sandboxApiKey}
                  onChange={event => setConfig(previousConfig => ({ ...previousConfig, sandboxApiKey: event.target.value }))}
                  placeholder={t('sandboxApiKeyPlaceholder')}
                />
                <p className="text-xs text-gray-500">{t('sandboxApiKeyHint')}</p>
                <div className="grid gap-4 md:grid-cols-2">
                  <TextInput
                    label={t('sandboxPollingIntervalMs')}
                    type="number"
                    value={config.sandboxPollingIntervalMs}
                    onChange={event => setConfig(previousConfig => ({ ...previousConfig, sandboxPollingIntervalMs: Number.parseInt(event.target.value, 10) || 1000 }))}
                  />
                  <TextInput
                    label={t('sandboxTimeoutSeconds')}
                    type="number"
                    value={config.sandboxTimeoutSeconds}
                    onChange={event => setConfig(previousConfig => ({ ...previousConfig, sandboxTimeoutSeconds: Number.parseInt(event.target.value, 10) || 60 }))}
                  />
                </div>
                <p className="text-xs text-gray-500">{t('sandboxProviderHint')}</p>
              </>
            ) : config.sandboxProvider === 'cerberus_lab' ? (
              <div className="space-y-4">
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">
                  <div className="font-semibold">{t('sandboxProvider_cerberus_lab')}</div>
                  <div className="mt-2">{t('sandboxProviderHintCerberusLab')}</div>
                </div>
                <ToggleField
                  label={t('sandboxDynamicExecutionEnabled')}
                  description={t('sandboxDynamicExecutionEnabledHint')}
                  checked={config.sandboxDynamicExecutionEnabled}
                  onChange={checked => setConfig(previousConfig => ({ ...previousConfig, sandboxDynamicExecutionEnabled: checked }))}
                />
                <TextInput
                  label={t('sandboxDynamicRuntimeSeconds')}
                  type="number"
                  value={config.sandboxDynamicRuntimeSeconds}
                  onChange={event => setConfig(previousConfig => ({ ...previousConfig, sandboxDynamicRuntimeSeconds: Number.parseInt(event.target.value, 10) || 45 }))}
                />
                <p className="text-xs text-gray-500">{t('sandboxDynamicRuntimeHint')}</p>
              </div>
            ) : (
              <p className="text-xs text-gray-500">{t('sandboxProvider_none')}</p>
            )}
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
