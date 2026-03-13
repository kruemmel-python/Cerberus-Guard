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
