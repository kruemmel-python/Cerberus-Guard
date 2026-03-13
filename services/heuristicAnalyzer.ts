import { AnalysisResult, AttackType, Configuration, Packet } from '../types';

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
  'ncat ',
  'mimikatz',
  'union select',
  'drop table',
  '../',
  '<?php',
];

interface SourceWindowState {
  packetTimestamps: number[];
  authAttempts: number[];
  portTouches: Array<{ port: number; timestamp: number }>;
}

export interface HeuristicEvaluation {
  result: AnalysisResult | null;
  needsDeepInspection: boolean;
}

const decodeHexSnippet = (hexValue: string) => {
  try {
    const bytes = new Uint8Array(
      hexValue.match(/.{1,2}/g)?.map(byte => Number.parseInt(byte, 16)).filter(byte => !Number.isNaN(byte)) ?? []
    );
    return new TextDecoder().decode(bytes).toLowerCase();
  } catch {
    return '';
  }
};

const prune = (timestamps: number[], cutoff: number) => timestamps.filter(timestamp => timestamp >= cutoff);

const buildResult = (
  packet: Packet,
  overrides: Partial<Omit<AnalysisResult, 'packet' | 'decisionSource' | 'matchedSignals'>> & {
    decisionSource?: AnalysisResult['decisionSource'];
    matchedSignals?: string[];
  }
): AnalysisResult => ({
  isSuspicious: false,
  attackType: AttackType.NONE,
  confidence: 0.05,
  explanation: 'No heuristic anomaly detected.',
  packet,
  decisionSource: overrides.decisionSource ?? 'heuristic',
  matchedSignals: overrides.matchedSignals ?? [],
  ...overrides,
});

export class HeuristicAnalyzer {
  private sourceState: Map<string, SourceWindowState>;

  constructor() {
    this.sourceState = new Map<string, SourceWindowState>();
  }

  reset() {
    this.sourceState.clear();
  }

  evaluate(packet: Packet, config: Configuration): HeuristicEvaluation {
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
    const matchedSignals: string[] = [];

    if (state.packetTimestamps.length >= DDOS_PACKET_THRESHOLD) {
      matchedSignals.push('rate.ddos.threshold');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.DDOS,
          confidence: 0.99,
          explanation: 'High packet rate from the same source indicates a volumetric attack.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    if (uniqueTouchedPorts.size >= PORT_SCAN_PORT_THRESHOLD) {
      matchedSignals.push('behavior.port_scan.multiple_ports');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.PORT_SCAN,
          confidence: 0.96,
          explanation: 'The same source probed many destination ports in a short time window.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    if (state.authAttempts.length >= BRUTE_FORCE_ATTEMPTS) {
      matchedSignals.push('behavior.brute_force.repeated_auth');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.BRUTE_FORCE,
          confidence: 0.94,
          explanation: 'Repeated authentication-oriented traffic suggests a brute-force attempt.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    if (payloadText && MALICIOUS_KEYWORDS.some(keyword => payloadText.includes(keyword))) {
      matchedSignals.push('payload.signature.known_malicious');
      return {
        result: buildResult(packet, {
          isSuspicious: true,
          attackType: AttackType.MALICIOUS_PAYLOAD,
          confidence: 0.97,
          explanation: 'Known malicious command patterns were found in the packet payload.',
          matchedSignals,
        }),
        needsDeepInspection: false,
      };
    }

    const touchesMonitoredPort = config.monitoringPorts.includes(packet.destinationPort);
    const targetsSensitivePort = AUTH_PORTS.has(packet.destinationPort) || touchesMonitoredPort;
    const containsPayload = packet.payloadSnippet.length > 0;
    const isCommonBenignPort = COMMON_BENIGN_PORTS.has(packet.destinationPort);

    if ((targetsSensitivePort && packet.direction === 'INBOUND') || (containsPayload && !isCommonBenignPort)) {
      matchedSignals.push('inspection.deep.required');
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

  getSourceState(sourceIp: string): SourceWindowState {
    const existing = this.sourceState.get(sourceIp);
    if (existing) {
      return existing;
    }

    const nextState: SourceWindowState = {
      packetTimestamps: [],
      authAttempts: [],
      portTouches: [],
    };
    this.sourceState.set(sourceIp, nextState);
    return nextState;
  }
}
