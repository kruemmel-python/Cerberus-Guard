export type TransportProtocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';

export type PacketDirection = 'INBOUND' | 'OUTBOUND' | 'UNKNOWN';

export type Layer7Protocol = 'HTTP' | 'DNS' | 'TLS' | 'SSH' | 'SMB' | 'RDP' | 'FTP' | 'SQL' | 'UNKNOWN';

export type DeploymentMode = 'standalone' | 'hub' | 'agent';

export type PayloadMaskingMode = 'strict' | 'raw_local_only';

export type ThreatIntelFeedFormat = 'plain' | 'spamhaus_drop' | 'json_array';
export type SandboxProvider = 'none' | 'cape' | 'cerberus_lab';
export type SandboxAnalysisStatus = 'queued' | 'running' | 'completed' | 'failed';
export type SandboxAnalysisStage =
  | 'queued'
  | 'static_analysis'
  | 'submitting'
  | 'waiting_for_report'
  | 'launching_sandbox'
  | 'guest_execution'
  | 'collecting_results'
  | 'completed'
  | 'failed';
export type SandboxVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

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
  | 'backpressure'
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

export interface SandboxAnalysisSummary {
  id: string;
  createdAt: string;
  updatedAt: string;
  status: SandboxAnalysisStatus;
  stage: SandboxAnalysisStage;
  stageMessage: string | null;
  provider: SandboxProvider;
  verdict: SandboxVerdict;
  summary: string;
  score: number | null;
  filePath: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  processName: string | null;
  trafficEventId: string | null;
  externalTaskId: string | null;
  reportUrl: string | null;
  errorMessage: string | null;
  signatures: string[];
  reportReady: boolean;
  reportPendingReason: string | null;
  sensorId: string;
  sensorName: string;
}

export interface SandboxLlmDebugPayload {
  analysisId: string;
  fileName: string;
  provider: SandboxProvider;
  updatedAt: string;
  reportReady: boolean;
  reportPendingReason: string | null;
  llmReview: Record<string, unknown> | null;
  llmReviewDebug: Record<string, unknown> | null;
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
  localLlmTimeoutSeconds: number;
  payloadMaskingMode: PayloadMaskingMode;
  sandboxEnabled: boolean;
  sandboxProvider: SandboxProvider;
  sandboxBaseUrl: string;
  sandboxApiKey: string;
  sandboxPollingIntervalMs: number;
  sandboxTimeoutSeconds: number;
  sandboxAutoSubmitSuspicious: boolean;
  sandboxPrioritizeLlmWorkloads: boolean;
  sandboxDynamicExecutionEnabled: boolean;
  sandboxDynamicRuntimeSeconds: number;
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
  serverInstanceId: string;
  config: ServerConfiguration;
  interfaces: CaptureInterface[];
  captureStatus: CaptureStatusPayload;
  metrics: MetricSnapshot;
  metricSeries: TrafficMetricPoint[];
  traffic: TrafficLogEntry[];
  logs: LogEntry[];
  artifacts: PcapArtifact[];
  sandboxAnalyses: SandboxAnalysisSummary[];
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
      type: 'sandbox-analysis';
      payload: SandboxAnalysisSummary;
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
