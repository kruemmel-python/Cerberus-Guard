import { GoogleGenAI, Type } from '@google/genai';
import { preparePacketForLlm } from './dataScrubber.js';
import { getProviderDefinition, getSelectedProviderSettings } from './llmProviders.js';

const ATTACK_TYPES = ['port_scan', 'brute_force', 'malicious_payload', 'ddos', 'none', 'other'];
const ANALYSIS_SYSTEM_PROMPT = `You are an expert network security analyst.
Return strictly valid raw JSON and nothing else.

Use one of these attack types:
- port_scan
- brute_force
- malicious_payload
- ddos
- none
- other

Confidence must be a number between 0.0 and 1.0.
Explain the decision in one concise sentence. Prefer structured metadata over raw payload when available.`;

const buildPacketProjection = (packet, config, definition) => {
  const prepared = preparePacketForLlm(packet, config, definition);

  return {
    packet_id: packet.id,
    timestamp: packet.timestamp,
    direction: packet.direction,
    capture_device: packet.captureDevice,
    sensor_id: packet.sensorId ?? '',
    sensor_name: packet.sensorName ?? '',
    source_ip: packet.sourceIp,
    source_port: packet.sourcePort,
    destination_ip: packet.destinationIp,
    destination_port: packet.destinationPort,
    protocol: packet.protocol,
    size: packet.size,
    layer7_protocol: packet.l7Protocol,
    layer7_metadata: prepared.l7Metadata,
    payload_snippet_text: prepared.payloadText,
    payload_snippet_hex: prepared.payloadHex,
    masking: prepared.masking,
  };
};

const buildSinglePacketPrompt = (packet, config, definition) =>
  `Analyze this captured network packet and return one JSON object.\n\n${JSON.stringify(buildPacketProjection(packet, config, definition), null, 2)}`;

const buildBatchPrompt = (packets, config, definition) =>
  `Analyze these captured network packets and return one JSON array with one result per packet.
Each result must include:
- packet_id
- is_suspicious
- attack_type
- confidence
- explanation

Packets:
${JSON.stringify(packets.map(packet => buildPacketProjection(packet, config, definition)), null, 2)}`;

const singleResponseSchema = {
  type: Type.OBJECT,
  properties: {
    is_suspicious: { type: Type.BOOLEAN },
    attack_type: { type: Type.STRING, enum: ATTACK_TYPES },
    confidence: { type: Type.NUMBER },
    explanation: { type: Type.STRING },
  },
  required: ['is_suspicious', 'attack_type', 'confidence', 'explanation'],
};

const batchResponseSchema = {
  type: Type.ARRAY,
  items: {
    type: Type.OBJECT,
    properties: {
      packet_id: { type: Type.STRING },
      is_suspicious: { type: Type.BOOLEAN },
      attack_type: { type: Type.STRING, enum: ATTACK_TYPES },
      confidence: { type: Type.NUMBER },
      explanation: { type: Type.STRING },
    },
    required: ['packet_id', 'is_suspicious', 'attack_type', 'confidence', 'explanation'],
  },
};

const isObject = value => typeof value === 'object' && value !== null && !Array.isArray(value);

const clampConfidence = value => {
  const numericValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numericValue)) {
    return 0;
  }
  return Math.max(0, Math.min(1, numericValue));
};

const normalizeAttackType = value => {
  const normalizedValue = typeof value === 'string' ? value.toLowerCase() : 'none';
  return ATTACK_TYPES.includes(normalizedValue) ? normalizedValue : 'none';
};

const parseJsonPayload = content => {
  const trimmed = content.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const arrayStart = trimmed.indexOf('[');
    const objectStart = trimmed.indexOf('{');
    const startIndex = arrayStart !== -1 && (objectStart === -1 || arrayStart < objectStart) ? arrayStart : objectStart;
    const endIndex = Math.max(trimmed.lastIndexOf(']'), trimmed.lastIndexOf('}'));
    if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
      throw new Error('Provider response did not contain valid JSON.');
    }
    return JSON.parse(trimmed.slice(startIndex, endIndex + 1));
  }
};

const normalizeAnalysisResult = (packet, payload, decisionSource = 'llm') => ({
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

const defaultBenign = (packet, explanation) => ({
  isSuspicious: false,
  attackType: 'none',
  confidence: 0,
  explanation,
  packet,
  decisionSource: 'llm',
  matchedSignals: [],
});

const ensureApiKey = definition => {
  if (!definition.requiresApiKey) {
    return '';
  }

  const apiKey = process.env[definition.envVar] || '';
  if (!apiKey) {
    throw new Error(`${definition.label} API key is not configured in ${definition.envVar}.`);
  }
  return apiKey;
};

const normalizeBaseUrl = (baseUrl, transport) => {
  const trimmedBaseUrl = baseUrl.trim().replace(/\/+$/, '');
  if (transport === 'openai-compatible') {
    return trimmedBaseUrl.replace(/\/chat\/completions$/i, '');
  }
  if (transport === 'anthropic') {
    return trimmedBaseUrl.replace(/\/v1\/messages$/i, '');
  }
  if (transport === 'ollama') {
    return trimmedBaseUrl.replace(/\/api\/chat$/i, '');
  }
  return trimmedBaseUrl;
};

const joinUrl = (baseUrl, path) => `${baseUrl.replace(/\/+$/, '')}${path}`;

const requestGemini = async (model, systemPrompt, prompt, schema, definition) => {
  const client = new GoogleGenAI({ apiKey: ensureApiKey(definition) });
  const response = await client.models.generateContent({
    model,
    contents: `${systemPrompt}\n\n${prompt}`,
    config: {
      responseMimeType: 'application/json',
      responseSchema: schema,
      temperature: 0.1,
    },
  });
  return parseJsonPayload(response.text);
};

const requestOpenAiCompatible = async (model, baseUrl, systemPrompt, prompt, definition) => {
  const headers = {
    'Content-Type': 'application/json',
  };

  if (definition.requiresApiKey) {
    headers.Authorization = `Bearer ${ensureApiKey(definition)}`;
  }

  const response = await fetch(joinUrl(baseUrl, '/chat/completions'), {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt },
      ],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    throw new Error(`Provider responded with ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const responseContent = data?.choices?.[0]?.message?.content;
  if (typeof responseContent !== 'string') {
    throw new Error('Provider returned an invalid response.');
  }
  return parseJsonPayload(responseContent);
};

const requestAnthropic = async (model, baseUrl, systemPrompt, prompt, definition) => {
  const response = await fetch(joinUrl(baseUrl, '/v1/messages'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ensureApiKey(definition),
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      system: systemPrompt,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1600,
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    throw new Error(`Anthropic responded with ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const responseContent = Array.isArray(data?.content)
    ? data.content
        .filter(item => item?.type === 'text' && typeof item.text === 'string')
        .map(item => item.text)
        .join('\n')
    : '';

  if (!responseContent) {
    throw new Error('Anthropic returned an invalid response.');
  }

  return parseJsonPayload(responseContent);
};

const requestOllama = async (model, baseUrl, systemPrompt, prompt) => {
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
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama responded with ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const responseContent = data?.message?.content;
  if (typeof responseContent !== 'string') {
    throw new Error('Ollama returned an invalid response.');
  }
  return parseJsonPayload(responseContent);
};

export const getProviderRuntime = config => {
  const definition = getProviderDefinition(config.llmProvider);
  const providerSettings = getSelectedProviderSettings(config);
  return {
    definition,
    model: providerSettings.model || definition.defaultModel,
    baseUrl: normalizeBaseUrl(providerSettings.baseUrl || definition.defaultBaseUrl, definition.transport),
  };
};

export const requestProviderJson = async (config, prompt, schema, options = {}) => {
  const runtime = getProviderRuntime(config);
  const systemPrompt = options.systemPrompt || ANALYSIS_SYSTEM_PROMPT;

  switch (runtime.definition.transport) {
    case 'gemini':
      return requestGemini(runtime.model, systemPrompt, prompt, schema, runtime.definition);
    case 'openai-compatible':
      return requestOpenAiCompatible(runtime.model, runtime.baseUrl, systemPrompt, prompt, runtime.definition);
    case 'anthropic':
      return requestAnthropic(runtime.model, runtime.baseUrl, systemPrompt, prompt, runtime.definition);
    case 'ollama':
      return requestOllama(runtime.model, runtime.baseUrl, systemPrompt, prompt);
    default:
      throw new Error(`Unsupported provider transport: ${runtime.definition.transport}`);
  }
};

export const analyzeTraffic = async (packet, config) => {
  try {
    const runtime = getProviderRuntime(config);
    const payload = await requestProviderJson(config, buildSinglePacketPrompt(packet, config, runtime.definition), singleResponseSchema, {
      systemPrompt: ANALYSIS_SYSTEM_PROMPT,
    });
    if (!isObject(payload)) {
      throw new Error('Provider did not return a JSON object.');
    }
    return normalizeAnalysisResult(packet, payload);
  } catch (error) {
    return defaultBenign(packet, error instanceof Error ? error.message : 'LLM analysis failed.');
  }
};

export const analyzeTrafficBatch = async (packets, config) => {
  if (packets.length === 0) {
    return [];
  }

  if (packets.length === 1) {
    return [await analyzeTraffic(packets[0], config)];
  }

  try {
    const runtime = getProviderRuntime(config);
    const payload = await requestProviderJson(config, buildBatchPrompt(packets, config, runtime.definition), batchResponseSchema, {
      systemPrompt: ANALYSIS_SYSTEM_PROMPT,
    });
    if (!Array.isArray(payload)) {
      throw new Error('Provider did not return a JSON array.');
    }

    const resultMap = new Map(
      payload.filter(isObject).filter(item => typeof item.packet_id === 'string').map(item => [item.packet_id, item])
    );

    return packets.map(packet => {
      const payloadItem = resultMap.get(packet.id);
      return payloadItem ? normalizeAnalysisResult(packet, payloadItem) : defaultBenign(packet, 'Batch analysis returned no decision for this packet.');
    });
  } catch (error) {
    return Promise.all(packets.map(packet => analyzeTraffic(packet, config)));
  }
};

export { Type };
