import net from 'node:net';

const DDOS_WINDOW_MS = 5_000;
const DDOS_PACKET_THRESHOLD = 150;
const PORT_SCAN_WINDOW_MS = 15_000;
const PORT_SCAN_PORT_THRESHOLD = 12;
const BRUTE_FORCE_WINDOW_MS = 30_000;
const BRUTE_FORCE_ATTEMPTS = 16;

const AUTH_PORTS = new Set([21, 22, 23, 25, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432]);
const COMMON_BENIGN_PORTS = new Set([53, 80, 123, 443, 853]);
const MALICIOUS_KEYWORDS = [
  'powershell',
  'invoke-expression',
  'cmd.exe',
  '/bin/sh',
  'wget ',
  'curl ',
  'nc -e',
  'mimikatz',
  'union select',
  'drop table',
  '../',
  '<?php',
];

const decodeHexSnippet = (hexValue) => {
  try {
    const bytes = new Uint8Array(
      hexValue.match(/.{1,2}/g)?.map(byte => Number.parseInt(byte, 16)).filter(byte => !Number.isNaN(byte)) ?? []
    );
    return new TextDecoder().decode(bytes).toLowerCase();
  } catch {
    return '';
  }
};

const prune = (timestamps, cutoff) => timestamps.filter(timestamp => timestamp >= cutoff);

const buildResult = (packet, overrides = {}) => ({
  isSuspicious: false,
  attackType: 'none',
  confidence: 0.05,
  explanation: 'No heuristic anomaly detected.',
  packet,
  decisionSource: 'heuristic',
  matchedSignals: [],
  ...overrides,
});

const getPacketFieldValue = (packet, field) => {
  switch (field) {
    case 'sourceIp':
      return packet.sourceIp;
    case 'destinationIp':
      return packet.destinationIp;
    case 'sourcePort':
      return packet.sourcePort;
    case 'destinationPort':
      return packet.destinationPort;
    case 'protocol':
      return packet.protocol;
    case 'direction':
      return packet.direction;
    case 'size':
      return packet.size;
    case 'l7Protocol':
      return packet.l7Protocol;
    case 'payloadSnippet':
      return packet.payloadSnippet;
    default:
      if (field.startsWith('l7.')) {
        return packet.l7Metadata[field.slice(3)] ?? '';
      }
      return '';
  }
};

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

const evaluateCondition = (packet, condition) => {
  const fieldValue = getPacketFieldValue(packet, condition.field);
  const normalizedValue = String(fieldValue);
  const numericFieldValue = Number(fieldValue);
  const numericConditionValue = Number(condition.value);
  const listValues = condition.value.split(',').map(item => item.trim()).filter(Boolean);

  switch (condition.operator) {
    case 'equals':
      return normalizedValue === condition.value;
    case 'not_equals':
      return normalizedValue !== condition.value;
    case 'greater_than':
      return Number.isFinite(numericFieldValue) && Number.isFinite(numericConditionValue) && numericFieldValue > numericConditionValue;
    case 'less_than':
      return Number.isFinite(numericFieldValue) && Number.isFinite(numericConditionValue) && numericFieldValue < numericConditionValue;
    case 'contains':
      return normalizedValue.toLowerCase().includes(condition.value.toLowerCase());
    case 'starts_with':
      return normalizedValue.toLowerCase().startsWith(condition.value.toLowerCase());
    case 'in_cidr':
      return matchesCidr(normalizedValue, condition.value);
    case 'not_in_cidr':
      return !matchesCidr(normalizedValue, condition.value);
    case 'in_list':
      return listValues.includes(normalizedValue);
    case 'not_in_list':
      return !listValues.includes(normalizedValue);
    default:
      return false;
  }
};

export class HeuristicAnalyzer {
  constructor() {
    this.sourceState = new Map();
  }

  reset() {
    this.sourceState.clear();
  }

  getSourceState(sourceIp) {
    const existing = this.sourceState.get(sourceIp);
    if (existing) {
      return existing;
    }

    const nextState = {
      packetTimestamps: [],
      authAttempts: [],
      portTouches: [],
    };
    this.sourceState.set(sourceIp, nextState);
    return nextState;
  }

  evaluate(packet, config) {
    for (const rule of config.customRules) {
      if (!rule.enabled) {
        continue;
      }

      const conditionResults = rule.conditions.map(condition => evaluateCondition(packet, condition));
      const matched = rule.matchMode === 'all' ? conditionResults.every(Boolean) : conditionResults.some(Boolean);

      if (matched) {
        return {
          result: buildResult(packet, {
            isSuspicious: rule.outcome.attackType !== 'none' && rule.outcome.actionType !== 'ALLOW',
            attackType: rule.outcome.attackType,
            confidence: rule.outcome.confidence,
            explanation: rule.outcome.explanation,
            decisionSource: 'custom_rule',
            matchedSignals: [`custom_rule:${rule.name}`],
            recommendedActionType: rule.outcome.actionType,
            recommendedTargetPort: rule.outcome.targetPort,
          }),
          needsDeepInspection: rule.outcome.needsDeepInspection,
        };
      }
    }

    const now = Date.parse(packet.timestamp) || Date.now();
    const state = this.getSourceState(packet.sourceIp);
    const payloadText = decodeHexSnippet(packet.payloadSnippet);

    state.packetTimestamps.push(now);
    state.authAttempts = prune(state.authAttempts, now - BRUTE_FORCE_WINDOW_MS);
    state.portTouches = state.portTouches.filter(entry => entry.timestamp >= now - PORT_SCAN_WINDOW_MS);
    state.packetTimestamps = prune(state.packetTimestamps, now - DDOS_WINDOW_MS);
    state.portTouches.push({ port: packet.destinationPort, timestamp: now });

    if (AUTH_PORTS.has(packet.destinationPort)) {
      state.authAttempts.push(now);
    }

    const uniqueTouchedPorts = new Set(state.portTouches.map(entry => entry.port));

    if (state.packetTimestamps.length >= DDOS_PACKET_THRESHOLD) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'ddos',
          confidence: 0.99,
          explanation: 'High packet rate from the same source indicates a volumetric attack.',
          matchedSignals: ['rate.ddos.threshold'],
          recommendedActionType: 'BLOCK',
        }),
        needsDeepInspection: false,
      };
    }

    if (uniqueTouchedPorts.size >= PORT_SCAN_PORT_THRESHOLD) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'port_scan',
          confidence: 0.96,
          explanation: 'The same source probed many destination ports in a short time window.',
          matchedSignals: ['behavior.port_scan.multiple_ports'],
          recommendedActionType: 'BLOCK',
        }),
        needsDeepInspection: false,
      };
    }

    if (state.authAttempts.length >= BRUTE_FORCE_ATTEMPTS) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'brute_force',
          confidence: 0.94,
          explanation: 'Repeated authentication-oriented traffic suggests a brute-force attempt.',
          matchedSignals: ['behavior.brute_force.repeated_auth'],
          recommendedActionType: 'BLOCK',
        }),
        needsDeepInspection: false,
      };
    }

    if (payloadText && MALICIOUS_KEYWORDS.some(keyword => payloadText.includes(keyword))) {
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: 'malicious_payload',
          confidence: 0.97,
          explanation: 'Known malicious command patterns were found in the packet payload.',
          matchedSignals: ['payload.signature.known_malicious'],
          recommendedActionType: 'REDIRECT',
          recommendedTargetPort: config.securePort,
        }),
        needsDeepInspection: false,
      };
    }

    if (packet.l7Protocol === 'SSH' && packet.l7Metadata.sshBanner && packet.direction === 'INBOUND') {
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    if (packet.l7Protocol === 'SMB' && packet.direction === 'INBOUND') {
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    const targetsSensitivePort = AUTH_PORTS.has(packet.destinationPort) || config.monitoringPorts.includes(packet.destinationPort);
    const carriesInspectableMetadata = packet.l7Protocol !== 'UNKNOWN' || packet.payloadSnippet.length > 0;
    const isCommonBenignPort = COMMON_BENIGN_PORTS.has(packet.destinationPort);

    if ((targetsSensitivePort && packet.direction === 'INBOUND') || (carriesInspectableMetadata && !isCommonBenignPort)) {
      return {
        result: null,
        needsDeepInspection: true,
      };
    }

    return {
      result: buildResult(packet, {
        confidence: 0.08,
        explanation: 'Traffic matched benign heuristic rules and did not require deep inspection.',
      }),
      needsDeepInspection: false,
    };
  }
}
