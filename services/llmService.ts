import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, AttackType, Configuration, Packet, ProviderTransport } from '../types';
import { getProviderDefinition, getSelectedProviderSettings } from './llmProviders';

const SYSTEM_PROMPT = `You are an expert network security analyst.
Return strictly valid raw JSON and nothing else.

Available attack types:
- port_scan
- brute_force
- malicious_payload
- ddos
- none
- other

Use "none" for benign traffic. Confidence must be a number between 0.0 and 1.0.
Explain the decision in one concise sentence.`;

const buildPacketProjection = (packet: Packet) => ({
  packet_id: packet.id,
  timestamp: packet.timestamp,
  direction: packet.direction,
  capture_device: packet.captureDevice,
  source_ip: packet.sourceIp,
  source_port: packet.sourcePort,
  destination_ip: packet.destinationIp,
  destination_port: packet.destinationPort,
  protocol: packet.protocol,
  size: packet.size,
  payload_snippet_hex: packet.payloadSnippet,
});

const buildSinglePacketPrompt = (packet: Packet) =>
  `Analyze this captured network packet and return one JSON object.

${JSON.stringify(buildPacketProjection(packet), null, 2)}`;

const buildBatchPrompt = (packets: Packet[]) =>
  `Analyze the following captured network packets and return one JSON array with one result per packet.
Each result must include:
- packet_id
- is_suspicious
- attack_type
- confidence
- explanation

Packets:
${JSON.stringify(packets.map(buildPacketProjection), null, 2)}`;

const analysisResultSchema = {
  type: Type.OBJECT,
  properties: {
    is_suspicious: { type: Type.BOOLEAN },
    attack_type: { type: Type.STRING, enum: Object.values(AttackType) },
    confidence: { type: Type.NUMBER },
    explanation: { type: Type.STRING },
  },
  required: ['is_suspicious', 'attack_type', 'confidence', 'explanation'],
};

const batchAnalysisResultSchema = {
  type: Type.ARRAY,
  items: {
    type: Type.OBJECT,
    properties: {
      packet_id: { type: Type.STRING },
      is_suspicious: { type: Type.BOOLEAN },
      attack_type: { type: Type.STRING, enum: Object.values(AttackType) },
      confidence: { type: Type.NUMBER },
      explanation: { type: Type.STRING },
    },
    required: ['packet_id', 'is_suspicious', 'attack_type', 'confidence', 'explanation'],
  },
};

const getDefaultBenignResult = (packet: Packet, explanation: string, decisionSource: AnalysisResult['decisionSource'] = 'llm'): AnalysisResult => ({
  isSuspicious: false,
  attackType: AttackType.NONE,
  confidence: 0.0,
  explanation,
  packet,
  decisionSource,
  matchedSignals: [],
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const clampConfidence = (value: unknown): number => {
  const numericValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numericValue)) {
    return 0.0;
  }
  return Math.min(1, Math.max(0, numericValue));
};

const normalizeAttackType = (value: unknown): AttackType => {
  if (typeof value !== 'string') {
    return AttackType.NONE;
  }

  const normalizedValue = value.toLowerCase();
  return Object.values(AttackType).includes(normalizedValue as AttackType)
    ? (normalizedValue as AttackType)
    : AttackType.NONE;
};

const parseJsonPayload = (content: string): unknown => {
  const trimmedContent = content.trim();

  try {
    return JSON.parse(trimmedContent);
  } catch {
    const arrayStart = trimmedContent.indexOf('[');
    const objectStart = trimmedContent.indexOf('{');
    const startIndex = arrayStart !== -1 && (objectStart === -1 || arrayStart < objectStart) ? arrayStart : objectStart;
    const endIndex = Math.max(trimmedContent.lastIndexOf(']'), trimmedContent.lastIndexOf('}'));

    if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
      throw new Error("Could not find valid JSON in the LLM response.");
    }

    return JSON.parse(trimmedContent.slice(startIndex, endIndex + 1));
  }
};

const normalizeAnalysisResult = (
  packet: Packet,
  payload: Record<string, unknown>,
  decisionSource: AnalysisResult['decisionSource'] = 'llm'
): AnalysisResult => ({
  isSuspicious: Boolean(payload.is_suspicious ?? payload.isSuspicious ?? false),
  attackType: normalizeAttackType(payload.attack_type ?? payload.attackType),
  confidence: clampConfidence(payload.confidence),
  explanation:
    typeof payload.explanation === 'string' && payload.explanation.trim()
      ? payload.explanation.trim()
      : 'Analysis incomplete.',
  packet,
  decisionSource,
  matchedSignals: [],
});

const normalizeBaseUrl = (baseUrl: string, transport: ProviderTransport): string => {
  const trimmedBaseUrl = baseUrl.trim().replace(/\/+$/, '');

  switch (transport) {
    case 'openai-compatible':
      return trimmedBaseUrl.replace(/\/chat\/completions$/i, '');
    case 'anthropic':
      return trimmedBaseUrl.replace(/\/v1\/messages$/i, '');
    case 'ollama':
      return trimmedBaseUrl.replace(/\/api\/chat$/i, '');
    default:
      return trimmedBaseUrl;
  }
};

const joinUrl = (baseUrl: string, path: string) => `${baseUrl.replace(/\/+$/, '')}${path}`;

const getResolvedProviderConfig = (config: Configuration) => {
  const definition = getProviderDefinition(config.llmProvider);
  const selectedSettings = getSelectedProviderSettings(config);

  return {
    definition,
    model: selectedSettings.model.trim() || definition.defaultModel,
    baseUrl: normalizeBaseUrl(selectedSettings.baseUrl || definition.defaultBaseUrl, definition.transport),
    apiKey: selectedSettings.apiKey.trim(),
  };
};

const ensureApiKey = (providerLabel: string, envVar: string, apiKey: string) => {
  if (apiKey) {
    return apiKey;
  }

  throw new Error(`${providerLabel} API key is not configured${envVar ? ` (expected ${envVar})` : ''}.`);
};

const requestFromGemini = async (
  model: string,
  apiKey: string,
  userPrompt: string,
  responseSchema: unknown
) => {
  const ai = new GoogleGenAI({ apiKey });
  const response = await ai.models.generateContent({
    model,
    contents: `${SYSTEM_PROMPT}\n\n${userPrompt}`,
    config: {
      responseMimeType: 'application/json',
      responseSchema,
      temperature: 0.1,
    },
  });

  return parseJsonPayload(response.text);
};

const requestFromOpenAiCompatible = async (
  model: string,
  baseUrl: string,
  apiKey: string,
  userPrompt: string,
  requiresApiKey: boolean
) => {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (requiresApiKey) {
    headers.Authorization = `Bearer ${ensureApiKey('OpenAI-compatible provider', '', apiKey)}`;
  } else if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }

  const response = await fetch(joinUrl(baseUrl, '/chat/completions'), {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Provider responded with ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const responseContent = data?.choices?.[0]?.message?.content;

  if (typeof responseContent !== 'string') {
    throw new Error('Provider returned an invalid response payload.');
  }

  return parseJsonPayload(responseContent);
};

const requestFromAnthropic = async (
  model: string,
  baseUrl: string,
  apiKey: string,
  userPrompt: string
) => {
  const response = await fetch(joinUrl(baseUrl, '/v1/messages'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ensureApiKey('Anthropic', 'ANTHROPIC_API_KEY', apiKey),
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: 'user',
          content: userPrompt,
        },
      ],
      max_tokens: 1200,
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Anthropic responded with ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const responseContent = Array.isArray(data?.content)
    ? data.content
        .filter((item: { type?: string; text?: string }) => item?.type === 'text' && typeof item.text === 'string')
        .map((item: { text: string }) => item.text)
        .join('\n')
    : '';

  if (!responseContent) {
    throw new Error('Anthropic returned an invalid response payload.');
  }

  return parseJsonPayload(responseContent);
};

const requestFromOllama = async (model: string, baseUrl: string, userPrompt: string) => {
  const response = await fetch(joinUrl(baseUrl, '/api/chat'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      stream: false,
      format: 'json',
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Ollama responded with ${response.status}: ${errorText}`);
  }

  const data = await response.json();
  const responseContent = data?.message?.content;

  if (typeof responseContent !== 'string') {
    throw new Error('Ollama returned an invalid response payload.');
  }

  return parseJsonPayload(responseContent);
};

const requestProviderJson = async (config: Configuration, userPrompt: string, responseSchema: unknown) => {
  const { definition, model, baseUrl, apiKey } = getResolvedProviderConfig(config);

  switch (definition.transport) {
    case 'gemini':
      return requestFromGemini(model, ensureApiKey(definition.label, definition.envVar, apiKey), userPrompt, responseSchema);
    case 'openai-compatible':
      return requestFromOpenAiCompatible(model, baseUrl, apiKey, userPrompt, definition.requiresApiKey);
    case 'anthropic':
      return requestFromAnthropic(model, baseUrl, apiKey, userPrompt);
    case 'ollama':
      return requestFromOllama(model, baseUrl, userPrompt);
    default:
      throw new Error(`Unsupported provider transport: ${definition.transport}`);
  }
};

export const analyzeTraffic = async (packet: Packet, config: Configuration): Promise<AnalysisResult> => {
  try {
    const payload = await requestProviderJson(config, buildSinglePacketPrompt(packet), analysisResultSchema);

    if (!isRecord(payload)) {
      throw new Error('Provider did not return a JSON object.');
    }

    return normalizeAnalysisResult(packet, payload);
  } catch (error) {
    console.error('LLM analysis failed:', error);
    return getDefaultBenignResult(packet, error instanceof Error ? error.message : 'LLM analysis failed.');
  }
};

export const analyzeTrafficBatch = async (packets: Packet[], config: Configuration): Promise<AnalysisResult[]> => {
  if (packets.length === 0) {
    return [];
  }

  if (packets.length === 1) {
    return [await analyzeTraffic(packets[0], config)];
  }

  try {
    const payload = await requestProviderJson(config, buildBatchPrompt(packets), batchAnalysisResultSchema);

    if (!Array.isArray(payload)) {
      throw new Error('Provider did not return a JSON array for batch analysis.');
    }

    const resultsByPacketId = new Map<string, Record<string, unknown>>();

    for (const item of payload) {
      if (isRecord(item) && typeof item.packet_id === 'string') {
        resultsByPacketId.set(item.packet_id, item);
      }
    }

    return packets.map(packet => {
      const result = resultsByPacketId.get(packet.id);
      return result
        ? normalizeAnalysisResult(packet, result)
        : getDefaultBenignResult(packet, 'Batch analysis returned no decision for this packet.');
    });
  } catch (error) {
    console.error('LLM batch analysis failed:', error);
    return Promise.all(
      packets.map(packet =>
        analyzeTraffic(packet, config).catch(innerError =>
          getDefaultBenignResult(packet, innerError instanceof Error ? innerError.message : 'LLM fallback failed.')
        )
      )
    );
  }
};
