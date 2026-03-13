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
