import { Configuration, LlmProvider, LlmProviderSettings, ProviderTransport } from '../types';

declare const __LLM_ENV__: Record<string, string>;

export interface ProviderDefinition {
  id: LlmProvider;
  label: string;
  transport: ProviderTransport;
  defaultModel: string;
  defaultBaseUrl: string;
  envVar: string;
  requiresApiKey: boolean;
  local: boolean;
}

const LLM_ENV = typeof __LLM_ENV__ === 'undefined' ? {} : __LLM_ENV__;

export const PROVIDER_DEFINITIONS: ProviderDefinition[] = [
  {
    id: 'gemini',
    label: 'Gemini',
    transport: 'gemini',
    defaultModel: 'gemini-2.5-flash',
    defaultBaseUrl: 'https://generativelanguage.googleapis.com',
    envVar: 'GEMINI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'openai',
    label: 'OpenAI',
    transport: 'openai-compatible',
    defaultModel: 'gpt-4.1-mini',
    defaultBaseUrl: 'https://api.openai.com/v1',
    envVar: 'OPENAI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'anthropic',
    label: 'Anthropic',
    transport: 'anthropic',
    defaultModel: 'claude-3-5-sonnet-latest',
    defaultBaseUrl: 'https://api.anthropic.com',
    envVar: 'ANTHROPIC_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'openrouter',
    label: 'OpenRouter',
    transport: 'openai-compatible',
    defaultModel: 'openai/gpt-4.1-mini',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    envVar: 'OPENROUTER_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'groq',
    label: 'Groq',
    transport: 'openai-compatible',
    defaultModel: 'llama-3.3-70b-versatile',
    defaultBaseUrl: 'https://api.groq.com/openai/v1',
    envVar: 'GROQ_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'mistral',
    label: 'Mistral',
    transport: 'openai-compatible',
    defaultModel: 'mistral-small-latest',
    defaultBaseUrl: 'https://api.mistral.ai/v1',
    envVar: 'MISTRAL_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    transport: 'openai-compatible',
    defaultModel: 'deepseek-chat',
    defaultBaseUrl: 'https://api.deepseek.com',
    envVar: 'DEEPSEEK_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'xai',
    label: 'xAI',
    transport: 'openai-compatible',
    defaultModel: 'grok-2-latest',
    defaultBaseUrl: 'https://api.x.ai/v1',
    envVar: 'XAI_API_KEY',
    requiresApiKey: true,
    local: false,
  },
  {
    id: 'lmstudio',
    label: 'LM Studio',
    transport: 'openai-compatible',
    defaultModel: 'local-model',
    defaultBaseUrl: 'http://localhost:1234/v1',
    envVar: '',
    requiresApiKey: false,
    local: true,
  },
  {
    id: 'ollama',
    label: 'Ollama',
    transport: 'ollama',
    defaultModel: 'llama3.2',
    defaultBaseUrl: 'http://localhost:11434',
    envVar: '',
    requiresApiKey: false,
    local: true,
  },
];

const providerMap = PROVIDER_DEFINITIONS.reduce<Record<LlmProvider, ProviderDefinition>>((accumulator, definition) => {
  accumulator[definition.id] = definition;
  return accumulator;
}, {} as Record<LlmProvider, ProviderDefinition>);

const getEnvApiKey = (envVar: string) => (envVar ? LLM_ENV[envVar] ?? '' : '');

export const getProviderDefinition = (provider: LlmProvider): ProviderDefinition => providerMap[provider];

export const createDefaultProviderSettings = (): Record<LlmProvider, LlmProviderSettings> =>
  PROVIDER_DEFINITIONS.reduce<Record<LlmProvider, LlmProviderSettings>>((accumulator, definition) => {
    accumulator[definition.id] = {
      model: definition.defaultModel,
      baseUrl: definition.defaultBaseUrl,
      apiKey: getEnvApiKey(definition.envVar),
    };
    return accumulator;
  }, {} as Record<LlmProvider, LlmProviderSettings>);

export const mergeProviderSettings = (
  savedSettings?: Partial<Record<LlmProvider, Partial<LlmProviderSettings>>>
): Record<LlmProvider, LlmProviderSettings> => {
  const defaults = createDefaultProviderSettings();

  if (!savedSettings) {
    return defaults;
  }

  return PROVIDER_DEFINITIONS.reduce<Record<LlmProvider, LlmProviderSettings>>((accumulator, definition) => {
    const savedProviderSettings = savedSettings[definition.id];
    accumulator[definition.id] = {
      ...defaults[definition.id],
      ...savedProviderSettings,
      apiKey: savedProviderSettings?.apiKey || defaults[definition.id].apiKey,
    };
    return accumulator;
  }, {} as Record<LlmProvider, LlmProviderSettings>);
};

export const getSelectedProviderSettings = (config: Configuration): LlmProviderSettings =>
  config.providerSettings[config.llmProvider];
