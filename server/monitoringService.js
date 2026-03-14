import crypto from 'node:crypto';
import {
  getServerConfiguration,
  getSandboxAnalysisById,
  insertLogEntry,
  insertPcapArtifact,
  insertTrafficEvent,
  listPcapArtifacts,
  listRecentLogs,
  listRecentSandboxAnalyses,
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
import { SandboxService } from './sandboxService.js';

const createId = () => crypto.randomUUID();
const THREAT_INCIDENT_COOLDOWN_MS = 15_000;

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
    this.recentThreatIncidents = new Map();
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
    this.sandboxService = new SandboxService({
      onLog: (level, message, details) => {
        this.emitLog(level, message, details);
      },
      onAnalysisUpdate: analysis => {
        this.broadcast({
          type: 'sandbox-analysis',
          payload: analysis,
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
    this.sandboxService.configure(this.configuration);
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
      sandboxApiKey: nextConfiguration.sandboxApiKey || this.configuration.sandboxApiKey || '',
      providerSettings: mergedProviderSettings,
    });
    if (previousSensorId !== this.configuration.sensorId) {
      deleteSensor(previousSensorId);
    }
    this.syncMetricSnapshots();
    this.threatIntelService.configure(this.configuration);
    this.fleetService.configure(this.configuration);
    this.sandboxService.configure(this.configuration);
    this.upsertLocalSensor();
    this.emitLog('INFO', 'Configuration updated', {
      llmProvider: this.configuration.llmProvider,
      deploymentMode: this.configuration.deploymentMode,
      threatIntelEnabled: this.configuration.threatIntelEnabled,
      payloadMaskingMode: this.configuration.payloadMaskingMode,
      sandboxEnabled: this.configuration.sandboxEnabled,
      sandboxProvider: this.configuration.sandboxProvider,
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
    this.sandboxService.pruneStaleAnalyses({ sensorId });
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
      sandboxAnalyses: listRecentSandboxAnalyses(25, sensorId),
      replayStatus: this.replayStatus,
      fleetStatus: {
        ...this.fleetService.getStatus(),
        connectedSensors: sensors.filter(sensor => !sensor.local && sensor.connected).length,
      },
      sensors,
      threatIntelStatus: this.threatIntelStatus,
    };
  }

  listSandboxAnalyses(limit = 25, sensorId = null) {
    this.sandboxService.pruneStaleAnalyses({ sensorId });
    return listRecentSandboxAnalyses(limit, sensorId);
  }

  shouldDeferTrafficLlmInspection() {
    if (!this.configuration.sandboxPrioritizeLlmWorkloads) {
      return false;
    }

    const providerDefinition = getProviderDefinition(this.configuration.llmProvider);
    if (!providerDefinition?.local) {
      return false;
    }

    if (this.configuration.sandboxProvider !== 'cerberus_lab') {
      return false;
    }

    return this.sandboxService.hasActiveAnalyses();
  }

  pruneThreatIncidentCooldowns(cutoffTimestamp) {
    for (const [incidentKey, lastSeenAt] of this.recentThreatIncidents.entries()) {
      if (lastSeenAt < cutoffTimestamp) {
        this.recentThreatIncidents.delete(incidentKey);
      }
    }
  }

  shouldEmitThreatIncident(packet, analysisResult, actionType) {
    const isThreat = analysisResult.isSuspicious || actionType === 'BLOCK' || actionType === 'REDIRECT';
    if (!isThreat) {
      return false;
    }

    const now = Date.now();
    this.pruneThreatIncidentCooldowns(now - THREAT_INCIDENT_COOLDOWN_MS);

    const incidentKey = [
      packet.sourceIp,
      packet.destinationIp,
      packet.destinationPort,
      packet.protocol,
      analysisResult.attackType,
      actionType,
    ].join('|');
    const lastSeenAt = this.recentThreatIncidents.get(incidentKey) ?? 0;
    this.recentThreatIncidents.set(incidentKey, now);
    return now - lastSeenAt >= THREAT_INCIDENT_COOLDOWN_MS;
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

    if (
      this.configuration.sandboxEnabled
      && this.configuration.sandboxAutoSubmitSuspicious
      && trafficEntry.isSuspicious
      && packet.localProcess?.executablePath
    ) {
      void this.analyzeLocalProcessFile({
        filePath: packet.localProcess.executablePath,
        processName: packet.localProcess.name ?? null,
        trafficEventId: trafficEntry.id,
      }).catch(error => {
        this.emitLog('ERROR', 'Automatic sandbox submission failed.', {
          error: error instanceof Error ? error.message : 'Sandbox submission failed.',
          filePath: packet.localProcess?.executablePath,
          trafficEventId: trafficEntry.id,
        });
      });
    }

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
        } else if (this.shouldDeferTrafficLlmInspection()) {
          analysisResult = {
            isSuspicious: false,
            attackType: 'none',
            confidence: 0.12,
            explanation: 'Deep inspection was deferred because Cerberus Lab currently has priority on the local LLM runtime.',
            packet,
            decisionSource: 'backpressure',
            matchedSignals: ['llm.backpressure.sandbox_priority'],
          };
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

    const shouldEmitThreatIncident = this.shouldEmitThreatIncident(packet, analysisResult, actionType);

    if (actionType === 'BLOCK' && this.configuration.autoBlockThreats && !this.configuration.blockedIps.includes(packet.sourceIp)) {
      this.configuration.blockedIps.push(packet.sourceIp);
      saveServerConfiguration(this.configuration);
      this.emitLog('WARN', `IP ${packet.sourceIp} auto-added to blocklist`, {
        sourceIp: packet.sourceIp,
      });
    }

    if (shouldEmitThreatIncident && actionType === 'BLOCK' && this.configuration.firewallIntegrationEnabled) {
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

    if (shouldEmitThreatIncident) {
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

    if (shouldEmitThreatIncident) {
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

    if (shouldEmitThreatIncident && actionType === 'BLOCK' && this.configuration.globalBlockPropagationEnabled) {
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

  async analyzeLocalProcessFile({ filePath, processName = null, trafficEventId = null }) {
    const analysis = await this.sandboxService.analyzeFile(filePath, {
      processName,
      trafficEventId,
      sensorId: this.configuration.sensorId,
      sensorName: this.configuration.sensorName,
    }, {
      requireEnabled: false,
    });

    this.broadcast({
      type: 'sandbox-analysis',
      payload: analysis,
    });

    return analysis;
  }

  async analyzeUploadedFile({ filePath, fileName, attachments = [] }) {
    const analysis = await this.sandboxService.analyzeFile(filePath, {
      fileName,
      sidecarFiles: attachments,
      processName: null,
      trafficEventId: null,
      sensorId: this.configuration.sensorId,
      sensorName: this.configuration.sensorName,
    }, {
      requireEnabled: false,
    });

    this.broadcast({
      type: 'sandbox-analysis',
      payload: analysis,
    });

    return analysis;
  }

  async retrySandboxAnalystReview(analysisId) {
    const analysis = getSandboxAnalysisById(analysisId, { includeRaw: true });
    if (!analysis) {
      throw new Error('Sandbox analysis not found.');
    }

    if (analysis.provider !== 'cerberus_lab') {
      throw new Error('Only Cerberus Lab analyses support analyst-review retry.');
    }

    if (analysis.status !== 'completed') {
      throw new Error('Analyst review can only be retried for completed analyses.');
    }

    const refreshedAnalysis = await this.sandboxService.refreshExistingAnalysis(analysis, { force: true });
    this.broadcast({
      type: 'sandbox-analysis',
      payload: refreshedAnalysis,
    });

    return refreshedAnalysis;
  }
}
