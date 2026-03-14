import { sanitizeUntrustedMetadataForLlm, sanitizeUntrustedTextForLlm } from './promptInjectionGuard.js';

const SENSITIVE_PATTERNS = [
  {
    label: 'credit_card',
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: '[REDACTED_CREDIT_CARD]',
  },
  {
    label: 'email',
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: '[REDACTED_EMAIL]',
  },
  {
    label: 'bearer_token',
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi,
    replacement: 'Bearer [REDACTED_TOKEN]',
  },
  {
    label: 'basic_auth',
    pattern: /\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]+\b/gi,
    replacement: 'Authorization: Basic [REDACTED_CREDENTIALS]',
  },
  {
    label: 'cookie',
    pattern: /\b(?:session|sessionid|csrftoken|token|auth|jwt|refresh_token)=([^;\s]+)/gi,
    replacement: (_match, token) => `[REDACTED_COOKIE:${token.length}]`,
  },
  {
    label: 'password',
    pattern: /\b(password|passwd|pwd)\s*[:=]\s*([^\s&]+)/gi,
    replacement: '$1=[REDACTED_PASSWORD]',
  },
  {
    label: 'api_key',
    pattern: /\b(api[_-]?key|secret|client_secret)\s*[:=]\s*([^\s&]+)/gi,
    replacement: '$1=[REDACTED_SECRET]',
  },
];

const decodeHexPayload = (hexValue) => {
  if (!hexValue || typeof hexValue !== 'string') {
    return '';
  }

  try {
    const bytes = new Uint8Array(
      hexValue.match(/.{1,2}/g)?.map(byte => Number.parseInt(byte, 16)).filter(byte => !Number.isNaN(byte)) ?? []
    );
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
};

const calculateEntropy = (value) => {
  if (!value) {
    return 0;
  }

  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
};

const redactHighEntropyTokens = (input) => {
  let redactions = 0;
  const output = input.replace(/\b[A-Za-z0-9+/=_\-]{20,}\b/g, token => {
    if (calculateEntropy(token) >= 3.5) {
      redactions += 1;
      return `[REDACTED_TOKEN:${token.length}]`;
    }
    return token;
  });

  return { output, redactions };
};

export const scrubText = (input) => {
  if (!input) {
    return {
      text: '',
      redactions: [],
      redactionCount: 0,
    };
  }

  let output = input;
  const redactions = [];

  for (const matcher of SENSITIVE_PATTERNS) {
    let matched = false;
    output = output.replace(matcher.pattern, (...args) => {
      matched = true;
      if (typeof matcher.replacement === 'function') {
        return matcher.replacement(...args);
      }
      return matcher.replacement;
    });
    if (matched) {
      redactions.push(matcher.label);
    }
  }

  const entropyRedaction = redactHighEntropyTokens(output);
  output = entropyRedaction.output;
  if (entropyRedaction.redactions > 0) {
    redactions.push('high_entropy_token');
  }

  return {
    text: output,
    redactions,
    redactionCount: redactions.length + entropyRedaction.redactions,
  };
};

export const scrubMetadata = (metadata) => {
  const nextMetadata = {};
  const redactions = new Set();

  for (const [key, value] of Object.entries(metadata ?? {})) {
    const scrubbed = scrubText(String(value ?? ''));
    nextMetadata[key] = scrubbed.text;
    scrubbed.redactions.forEach(redaction => redactions.add(`${key}:${redaction}`));
  }

  return {
    metadata: nextMetadata,
    redactions: [...redactions],
  };
};

export const preparePacketForLlm = (packet, config, providerDefinition) => {
  const decodedPayload = decodeHexPayload(packet.payloadSnippet);
  const shouldScrub = config.payloadMaskingMode === 'strict' || !providerDefinition.local;

  const sanitizeUntrustedContent = (payloadText, l7Metadata) => {
    const sanitizedPayload = sanitizeUntrustedTextForLlm(payloadText, 320);
    const sanitizedMetadata = sanitizeUntrustedMetadataForLlm(l7Metadata, { maxLength: 240 });

    return {
      payloadText: sanitizedPayload.text,
      l7Metadata: sanitizedMetadata.metadata,
      promptInjectionSignals: [...new Set([...sanitizedPayload.signals, ...sanitizedMetadata.signals])],
    };
  };

  if (!shouldScrub) {
    const sanitized = sanitizeUntrustedContent(decodedPayload, packet.l7Metadata);
    return {
      payloadText: sanitized.payloadText,
      payloadHex: packet.payloadSnippet,
      l7Metadata: sanitized.l7Metadata,
      promptInjectionSignals: sanitized.promptInjectionSignals,
      masking: {
        applied: false,
        redactions: [],
      },
    };
  }

  const scrubbedPayload = scrubText(decodedPayload);
  const scrubbedMetadata = scrubMetadata(packet.l7Metadata);
  const sanitized = sanitizeUntrustedContent(scrubbedPayload.text, scrubbedMetadata.metadata);

  return {
    payloadText: sanitized.payloadText,
    payloadHex: '',
    l7Metadata: sanitized.l7Metadata,
    promptInjectionSignals: sanitized.promptInjectionSignals,
    masking: {
      applied: true,
      redactions: [...new Set([...scrubbedPayload.redactions, ...scrubbedMetadata.redactions])],
    },
  };
};
