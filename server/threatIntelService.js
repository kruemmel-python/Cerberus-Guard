import net from 'node:net';
import { listThreatIntelIndicators, replaceThreatIntelIndicators } from './db.js';

const normalizeIndicator = (value) => value.trim();

const matchesCidr = (ipAddress, cidrNotation) => {
  const [networkAddress, prefixLengthText] = cidrNotation.split('/');
  const prefixLength = Number(prefixLengthText);
  const family = net.isIP(networkAddress);
  if (!family || !net.isIP(ipAddress) || !Number.isInteger(prefixLength)) {
    return false;
  }

  const blockList = new net.BlockList();
  blockList.addSubnet(networkAddress, prefixLength, family === 6 ? 'ipv6' : 'ipv4');
  return blockList.check(ipAddress, family === 6 ? 'ipv6' : 'ipv4');
};

const parsePlainIndicators = (text) =>
  text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith(';'))
    .map(line => line.split(/[,\s;]/)[0]?.trim())
    .filter(Boolean)
    .map(indicator => ({
      indicator: normalizeIndicator(indicator),
      indicatorType: indicator.includes('/') ? 'cidr' : 'ip',
      label: 'plain_feed',
      confidence: 0.98,
    }));

const parseSpamhausDrop = (text) =>
  text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith(';') && !line.startsWith('#'))
    .map(line => {
      const [indicator, label] = line.split(';').map(part => part.trim());
      return {
        indicator: normalizeIndicator(indicator),
        indicatorType: indicator.includes('/') ? 'cidr' : 'ip',
        label: label || 'spamhaus_drop',
        confidence: 1,
      };
    })
    .filter(item => item.indicator);

const parseJsonArray = (text) => {
  const payload = JSON.parse(text);
  if (!Array.isArray(payload)) {
    return [];
  }

  return payload
    .map(item => {
      if (typeof item === 'string') {
        return {
          indicator: normalizeIndicator(item),
          indicatorType: item.includes('/') ? 'cidr' : 'ip',
          label: 'json_feed',
          confidence: 0.95,
        };
      }

      if (item && typeof item === 'object' && typeof item.indicator === 'string') {
        return {
          indicator: normalizeIndicator(item.indicator),
          indicatorType: item.indicator.includes('/') ? 'cidr' : 'ip',
          label: typeof item.label === 'string' ? item.label : 'json_feed',
          confidence: typeof item.confidence === 'number' ? item.confidence : 0.95,
          metadata: item,
        };
      }

      return null;
    })
    .filter(Boolean);
};

const parseSourceResponse = (source, text) => {
  switch (source.format) {
    case 'spamhaus_drop':
      return parseSpamhausDrop(text);
    case 'json_array':
      return parseJsonArray(text);
    case 'plain':
    default:
      return parsePlainIndicators(text);
  }
};

export class ThreatIntelService {
  constructor({ onStatusChange, onLog }) {
    this.onStatusChange = onStatusChange;
    this.onLog = onLog;
    this.status = {
      enabled: false,
      loadedIndicators: 0,
      sourceCount: 0,
      lastRefreshAt: null,
      lastError: null,
      refreshing: false,
    };
    this.refreshTimer = null;
    this.exactMatches = new Map();
    this.cidrMatches = [];
    this.loadIndicatorsFromDb();
  }

  loadIndicatorsFromDb() {
    const indicators = listThreatIntelIndicators();
    this.exactMatches.clear();
    this.cidrMatches = [];

    indicators.forEach(indicator => {
      if (indicator.indicatorType === 'cidr') {
        this.cidrMatches.push(indicator);
        return;
      }

      const existing = this.exactMatches.get(indicator.indicator) ?? [];
      existing.push(indicator);
      this.exactMatches.set(indicator.indicator, existing);
    });

    this.status.loadedIndicators = indicators.length;
  }

  getStatus() {
    return {
      ...this.status,
    };
  }

  stop() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  configure(config) {
    this.stop();
    this.status.enabled = config.threatIntelEnabled;
    this.status.sourceCount = config.threatIntelSources.length;
    this.onStatusChange(this.getStatus());

    if (!config.threatIntelEnabled) {
      return;
    }

    const intervalMs = Math.max(config.threatIntelRefreshHours, 1) * 60 * 60 * 1000;
    this.refreshTimer = setInterval(() => {
      void this.refresh(config);
    }, intervalMs);

    if (!this.status.lastRefreshAt) {
      void this.refresh(config);
    }
  }

  async refresh(config) {
    if (!config.threatIntelEnabled) {
      return this.getStatus();
    }

    const enabledSources = config.threatIntelSources.filter(source => source.enabled);
    const disabledSources = config.threatIntelSources.filter(source => !source.enabled);
    this.status = {
      ...this.status,
      enabled: true,
      sourceCount: config.threatIntelSources.length,
      refreshing: true,
      lastError: null,
    };
    this.onStatusChange(this.getStatus());

    try {
      for (const source of disabledSources) {
        replaceThreatIntelIndicators(source, []);
      }

      for (const source of enabledSources) {
        const response = await fetch(source.url);
        if (!response.ok) {
          throw new Error(`Threat intel source ${source.name} responded with ${response.status}.`);
        }

        const text = await response.text();
        const indicators = parseSourceResponse(source, text);
        replaceThreatIntelIndicators(source, indicators);
      }

      this.loadIndicatorsFromDb();
      this.status = {
        ...this.status,
        enabled: true,
        sourceCount: config.threatIntelSources.length,
        lastRefreshAt: new Date().toISOString(),
        lastError: null,
        refreshing: false,
      };
      this.onLog('INFO', 'Threat intelligence feeds refreshed.', {
        loadedIndicators: this.status.loadedIndicators,
        sources: enabledSources.length,
      });
    } catch (error) {
      this.status = {
        ...this.status,
        enabled: true,
        sourceCount: config.threatIntelSources.length,
        lastError: error instanceof Error ? error.message : 'Threat intelligence refresh failed.',
        refreshing: false,
      };
      this.onLog('ERROR', 'Threat intelligence refresh failed.', {
        error: this.status.lastError,
      });
    }

    this.onStatusChange(this.getStatus());
    return this.getStatus();
  }

  lookupIp(ipAddress) {
    const exactMatches = this.exactMatches.get(ipAddress);
    if (exactMatches && exactMatches.length > 0) {
      const [match] = exactMatches;
      return {
        indicator: match.indicator,
        sourceName: match.sourceName,
        label: match.label || 'threat_intel',
        confidence: match.confidence ?? 1,
      };
    }

    for (const indicator of this.cidrMatches) {
      if (matchesCidr(ipAddress, indicator.indicator)) {
        return {
          indicator: indicator.indicator,
          sourceName: indicator.sourceName,
          label: indicator.label || 'threat_intel',
          confidence: indicator.confidence ?? 1,
        };
      }
    }

    return null;
  }
}
