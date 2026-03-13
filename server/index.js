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
  listRecentSandboxAnalyses,
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
const sandboxAnalyzeSchema = z.object({
  path: z.string().trim().min(1),
  processName: z.string().trim().optional().nullable(),
  trafficEventId: z.string().trim().optional().nullable(),
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

app.get('/api/sandbox/analyses', (request, response) => {
  const limit = Number(request.query.limit || 25);
  const sensorId = typeof request.query.sensorId === 'string' && request.query.sensorId.trim() ? request.query.sensorId.trim() : null;
  response.json({
    analyses: listRecentSandboxAnalyses(limit, sensorId),
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

app.post('/api/sandbox/analyze-process', async (request, response) => {
  try {
    const payload = sandboxAnalyzeSchema.parse(request.body);
    const analysis = await monitoringService.analyzeLocalProcessFile({
      filePath: payload.path,
      processName: payload.processName || null,
      trafficEventId: payload.trafficEventId || null,
    });
    response.json({
      ok: true,
      analysis,
    });
  } catch (error) {
    const failedAnalysis = error?.analysis;
    if (failedAnalysis) {
      monitoringService.broadcast?.({
        type: 'sandbox-analysis',
        payload: failedAnalysis,
      });
    }
    response.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : 'Sandbox analysis failed.',
      analysis: failedAnalysis ?? null,
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
