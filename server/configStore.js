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

const sandboxProviderSchema = z.enum(['none', 'cape', 'cerberus_lab']);

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
  localLlmTimeoutSeconds: z.number().int().min(30).max(900),
  payloadMaskingMode: z.enum(['strict', 'raw_local_only']),
  sandboxEnabled: z.boolean(),
  sandboxProvider: sandboxProviderSchema,
  sandboxBaseUrl: z.string().trim().min(1),
  sandboxApiKey: z.string().optional().default(''),
  sandboxPollingIntervalMs: z.number().int().min(1000).max(60000),
  sandboxTimeoutSeconds: z.number().int().min(30).max(3600),
  sandboxAutoSubmitSuspicious: z.boolean(),
  sandboxPrioritizeLlmWorkloads: z.boolean(),
  sandboxDynamicExecutionEnabled: z.boolean(),
  sandboxDynamicRuntimeSeconds: z.number().int().min(10).max(600),
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
  sandboxApiKey: '',
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
