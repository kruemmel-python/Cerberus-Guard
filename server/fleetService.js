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
