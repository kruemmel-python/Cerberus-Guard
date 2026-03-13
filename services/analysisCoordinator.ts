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
