import { LRUCache } from 'lru-cache';
import { analyzeTrafficBatch } from './llmService.js';

export class AnalysisCoordinatorResetError extends Error {
  constructor(message = 'Analysis queue reset.') {
    super(message);
    this.name = 'AnalysisCoordinatorResetError';
    this.code = 'ANALYSIS_QUEUE_RESET';
  }
}

export class AnalysisCoordinator {
  constructor() {
    this.cache = new LRUCache({ max: 5000 });
    this.queues = new Map();
  }

  isCacheableResult(result) {
    const explanation = typeof result?.explanation === 'string' ? result.explanation.toLowerCase() : '';
    return !(
      explanation === 'analysis incomplete.'
      || explanation.includes('incomplete analysis json')
      || explanation.includes('incomplete decision json')
      || explanation.includes('did not return a json object')
      || explanation.includes('returned no decision')
      || explanation.includes('provider response did not contain valid json')
    );
  }

  reset(reason = 'Analysis queue reset.') {
    for (const queue of this.queues.values()) {
      if (queue.timer) {
        clearTimeout(queue.timer);
        queue.timer = null;
      }
      const queuedItems = [...queue.items];
      queue.items = [];
      queuedItems.forEach(item => item.reject(new AnalysisCoordinatorResetError(reason)));
    }
    this.queues.clear();
    this.cache.clear();
  }

  getCacheKey(packet) {
    return `${packet.sourceIp}:${packet.destinationIp}:${packet.destinationPort}:${packet.protocol}:${packet.l7Protocol}`;
  }

  getQueueKey(config) {
    const providerSettings = config.providerSettings[config.llmProvider];
    return JSON.stringify({
      provider: config.llmProvider,
      model: providerSettings.model,
      baseUrl: providerSettings.baseUrl,
    });
  }

  getOrCreateQueue(queueKey) {
    const existing = this.queues.get(queueKey);
    if (existing) {
      return existing;
    }

    const queue = {
      items: [],
      timer: null,
    };
    this.queues.set(queueKey, queue);
    return queue;
  }

  async analyze(packet, config) {
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
        void this.flushQueue(queueKey);
        return;
      }

      if (!queue.timer) {
        queue.timer = setTimeout(() => {
          void this.flushQueue(queueKey);
        }, config.batchWindowMs);
      }
    });
  }

  async flushQueue(queueKey) {
    const queue = this.queues.get(queueKey);
    if (!queue || queue.items.length === 0) {
      return;
    }

    if (queue.timer) {
      clearTimeout(queue.timer);
      queue.timer = null;
    }

    const items = [...queue.items];
    queue.items = [];
    const [firstItem] = items;
    if (!firstItem) {
      return;
    }

    try {
      const results = await analyzeTrafficBatch(items.map(item => item.packet), firstItem.config);
      results.forEach((result, index) => {
        const item = items[index];
        if (!item) {
          return;
        }
        if (this.isCacheableResult(result)) {
          this.cache.set(this.getCacheKey(item.packet), {
            isSuspicious: result.isSuspicious,
            attackType: result.attackType,
            confidence: result.confidence,
            explanation: result.explanation,
            matchedSignals: result.matchedSignals,
            recommendedActionType: result.recommendedActionType,
            recommendedTargetPort: result.recommendedTargetPort,
          }, {
            ttl: item.config.cacheTtlSeconds * 1000,
          });
        }
        item.resolve(result);
      });
    } catch (error) {
      items.forEach(item => item.reject(error));
    }
  }
}
