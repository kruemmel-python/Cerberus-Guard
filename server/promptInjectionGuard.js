const PROMPT_INJECTION_PATTERNS = [
  {
    label: 'ignore_previous_instructions',
    pattern: /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|messages?|context)\b/gi,
  },
  {
    label: 'role_override',
    pattern: /\b(?:you are|act as|behave as|pretend to be|assume the role of)\b/gi,
  },
  {
    label: 'system_prompt_reference',
    pattern: /\b(?:system prompt|developer message|hidden instruction|assistant message|jailbreak)\b/gi,
  },
  {
    label: 'response_override',
    pattern: /\b(?:reply|respond|output|return)\s+(?:with|only|exactly)\b/gi,
  },
  {
    label: 'tool_request',
    pattern: /\b(?:call|invoke|use)\s+(?:the\s+)?(?:tool|function|plugin|browser|shell)\b/gi,
  },
  {
    label: 'safety_bypass',
    pattern: /\b(?:bypass|disable|override)\s+(?:safety|guardrails|policy|policies|restrictions)\b/gi,
  },
  {
    label: 'chat_markup',
    pattern: /(?:<\|(?:system|assistant|user)[^>]*\|>|```(?:system|assistant|user))/gi,
  },
];

const normalizeWhitespace = value => String(value ?? '').replace(/\s+/g, ' ').trim();

export const collectPromptInjectionSignals = (value) => {
  const normalized = normalizeWhitespace(value);
  if (!normalized) {
    return [];
  }

  const signals = [];
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.pattern.test(normalized)) {
      signals.push(pattern.label);
    }
    pattern.pattern.lastIndex = 0;
  }
  return [...new Set(signals)];
};

export const sanitizeUntrustedTextForLlm = (value, maxLength = 240) => {
  const normalized = normalizeWhitespace(value);
  if (!normalized) {
    return {
      text: '',
      signals: [],
    };
  }

  let sanitized = normalized;
  const signals = collectPromptInjectionSignals(normalized);

  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    sanitized = sanitized.replace(
      pattern.pattern,
      `[UNTRUSTED_INSTRUCTION_${pattern.label.toUpperCase()}]`
    );
    pattern.pattern.lastIndex = 0;
  }

  if (sanitized.length > maxLength) {
    sanitized = `${sanitized.slice(0, Math.max(0, maxLength - 3))}...`;
  }

  return {
    text: sanitized,
    signals,
  };
};

export const sanitizeUntrustedListForLlm = (values, { limit = 10, maxLength = 240 } = {}) => {
  const allSignals = new Set();
  const sanitizedValues = [];

  for (const value of values ?? []) {
    const sanitized = sanitizeUntrustedTextForLlm(value, maxLength);
    sanitized.signals.forEach(signal => allSignals.add(signal));
    if (sanitized.text) {
      sanitizedValues.push(sanitized.text);
    }
    if (sanitizedValues.length >= limit) {
      break;
    }
  }

  return {
    values: [...new Set(sanitizedValues)],
    signals: [...allSignals],
  };
};

export const sanitizeUntrustedMetadataForLlm = (metadata, { maxLength = 240 } = {}) => {
  const sanitizedMetadata = {};
  const allSignals = new Set();

  for (const [key, value] of Object.entries(metadata ?? {})) {
    const sanitized = sanitizeUntrustedTextForLlm(value, maxLength);
    sanitizedMetadata[key] = sanitized.text;
    sanitized.signals.forEach(signal => allSignals.add(`${key}:${signal}`));
  }

  return {
    metadata: sanitizedMetadata,
    signals: [...allSignals],
  };
};
