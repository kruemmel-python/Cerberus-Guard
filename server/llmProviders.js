import { PROVIDER_DEFINITIONS } from './defaultConfig.js';

const providerMap = new Map(PROVIDER_DEFINITIONS.map(definition => [definition.id, definition]));

export const getProviderDefinition = (providerId) => providerMap.get(providerId);

export const getSelectedProviderSettings = (config) => config.providerSettings[config.llmProvider];
