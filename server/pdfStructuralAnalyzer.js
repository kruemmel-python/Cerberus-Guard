import zlib from 'node:zlib';
import { parsePortableExecutable } from './peParser.js';

const MAX_SNIPPETS = 8;
const MAX_NAMES = 12;
const MAX_URLS = 12;
const MAX_STREAM_BYTES_TO_DECODE = 2 * 1024 * 1024;

const toUniqueList = values => [...new Set(values.filter(Boolean).map(value => String(value).trim()).filter(Boolean))];

const computeEntropy = buffer => {
  if (!buffer?.length) {
    return 0;
  }

  const histogram = new Array(256).fill(0);
  for (const value of buffer) {
    histogram[value] += 1;
  }

  let entropy = 0;
  for (const count of histogram) {
    if (!count) {
      continue;
    }
    const probability = count / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

const decodePdfNameEscapes = value => String(value || '').replace(/#([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));

const extractSnippet = (text, index, matchLength = 0, radius = 80) => {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + matchLength + radius);
  return text
    .slice(start, end)
    .replace(/\s+/g, ' ')
    .trim();
};

const collectRegexSnippets = (text, expression) => {
  const snippets = [];
  const regex = new RegExp(expression.source, expression.flags.includes('g') ? expression.flags : `${expression.flags}g`);
  let match = regex.exec(text);
  while (match) {
    snippets.push(extractSnippet(text, match.index, match[0].length));
    match = regex.exec(text);
  }
  return toUniqueList(snippets).slice(0, MAX_SNIPPETS);
};

const decodePdfLiteral = value => decodePdfNameEscapes(String(value || '').replace(/\\([nrtbf()\\])/g, (_, escaped) => {
  switch (escaped) {
    case 'n':
      return '\n';
    case 'r':
      return '\r';
    case 't':
      return '\t';
    case 'b':
      return '\b';
    case 'f':
      return '\f';
    default:
      return escaped;
  }
}));

const decodePdfHexString = value => {
  const normalized = String(value || '').replace(/[^0-9a-fA-F]/g, '');
  if (!normalized) {
    return '';
  }
  const padded = normalized.length % 2 === 0 ? normalized : `${normalized}0`;
  return Buffer.from(padded, 'hex').toString('utf8').replace(/\u0000/g, '').trim();
};

const extractPdfNames = objectText => {
  const names = [];
  const literalPattern = /\/(?:UF|F)\s*\(([^)\r\n]{1,260})\)/gi;
  let literalMatch = literalPattern.exec(objectText);
  while (literalMatch) {
    names.push(decodePdfLiteral(literalMatch[1]));
    literalMatch = literalPattern.exec(objectText);
  }

  const hexPattern = /\/(?:UF|F)\s*<([0-9a-fA-F\s]{2,520})>/gi;
  let hexMatch = hexPattern.exec(objectText);
  while (hexMatch) {
    names.push(decodePdfHexString(hexMatch[1]));
    hexMatch = hexPattern.exec(objectText);
  }

  return toUniqueList(names).slice(0, MAX_NAMES);
};

const extractPdfUris = objectText => {
  const urls = [];
  const literalPattern = /\/URI\s*\(([^)\r\n]{1,400})\)/gi;
  let literalMatch = literalPattern.exec(objectText);
  while (literalMatch) {
    urls.push(decodePdfLiteral(literalMatch[1]));
    literalMatch = literalPattern.exec(objectText);
  }

  const hexPattern = /\/URI\s*<([0-9a-fA-F\s]{2,800})>/gi;
  let hexMatch = hexPattern.exec(objectText);
  while (hexMatch) {
    urls.push(decodePdfHexString(hexMatch[1]));
    hexMatch = hexPattern.exec(objectText);
  }

  return toUniqueList(urls).slice(0, MAX_URLS);
};

const EMBEDDED_SIGNATURES = [
  { label: 'portable-executable', pattern: Buffer.from('4d5a', 'hex') },
  { label: 'zip-archive', pattern: Buffer.from('504b0304', 'hex') },
  { label: 'pdf-document', pattern: Buffer.from('%PDF-') },
  { label: 'html-script', pattern: Buffer.from('<script', 'utf8') },
];

const detectEmbeddedPayloadSignatures = (buffer, offsetBase = 0) => {
  const hits = [];
  for (const signature of EMBEDDED_SIGNATURES) {
    let index = buffer.indexOf(signature.pattern);
    while (index !== -1) {
      const hit = {
        type: signature.label,
        offset: offsetBase + index,
      };
      if (signature.label === 'portable-executable') {
        const peMetadata = parsePortableExecutable(buffer.subarray(index));
        if (peMetadata) {
          hit.validated = true;
          hit.validation = {
            machine: peMetadata.machine,
            subsystem: peMetadata.subsystem,
            sectionCount: Array.isArray(peMetadata.sections) ? peMetadata.sections.length : 0,
            compileTimestamp: peMetadata.compileTimestamp || null,
            entryPointRva: peMetadata.entryPointRva || null,
          };
        } else {
          hit.validated = false;
        }
      }
      hits.push(hit);
      index = buffer.indexOf(signature.pattern, index + 1);
    }
  }
  return hits;
};

const safeInflatePdfStream = streamBytes => {
  if (!streamBytes?.length || streamBytes.length > MAX_STREAM_BYTES_TO_DECODE) {
    return null;
  }

  try {
    return zlib.inflateSync(streamBytes);
  } catch {
    try {
      return zlib.inflateRawSync(streamBytes);
    } catch {
      return null;
    }
  }
};

const inspectDecodedPdfText = (decodedText, collectors) => {
  const {
    javascriptIndicators,
    autoActionIndicators,
    launchIndicators,
    embeddedFileIndicators,
    uriIndicators,
    suspiciousTextIndicators,
    suspiciousTextSnippets,
  } = collectors;

  const decodedPatterns = [
    { pattern: /(?:app\.launchURL|this\.submitForm|exportDataObject|importDataObject|eval\s*\(|unescape\s*\()/gi, target: javascriptIndicators, label: 'Decoded stream contained JavaScript API usage.' },
    { pattern: /(?:\/OpenAction|\/AA\b)/gi, target: autoActionIndicators, label: 'Decoded stream contained automatic action directives.' },
    { pattern: /(?:\/Launch\b|cmd\.exe|powershell(?:\.exe)?)/gi, target: launchIndicators, label: 'Decoded stream referenced launch-style execution.' },
    { pattern: /(?:\/EmbeddedFile\b|\/EmbeddedFiles\b|\/Type\s*\/Filespec\b)/gi, target: embeddedFileIndicators, label: 'Decoded stream referenced embedded files.' },
    { pattern: /(?:https?:\/\/[^\s"'<>]+|\/URI\b)/gi, target: uriIndicators, label: 'Decoded stream referenced external URIs.' },
  ];

  decodedPatterns.forEach(({ pattern, target, label }) => {
    if (pattern.test(decodedText)) {
      target.push(label);
      suspiciousTextSnippets.push(...collectRegexSnippets(decodedText, pattern));
    }
  });

  if (/(?:powershell|cmd\.exe|rundll32|javascript:|eval\s*\(|fromCharCode|base64)/i.test(decodedText)) {
    suspiciousTextIndicators.push('Decoded stream contained suspicious script-like content.');
    suspiciousTextSnippets.push(...collectRegexSnippets(decodedText, /(?:powershell|cmd\.exe|rundll32|javascript:|eval\s*\(|fromCharCode|base64)/gi));
  }
};

export const analyzePdfStructure = buffer => {
  const text = buffer.toString('latin1');
  const objectPattern = /(\d+)\s+(\d+)\s+obj\b/g;
  const objects = [];
  let objectMatch = objectPattern.exec(text);
  while (objectMatch) {
    const start = objectMatch.index;
    const end = text.indexOf('endobj', start);
    if (end === -1) {
      break;
    }
    objects.push({
      number: Number.parseInt(objectMatch[1], 10),
      generation: Number.parseInt(objectMatch[2], 10),
      start,
      end: end + 6,
      text: text.slice(start, end + 6),
    });
    objectMatch = objectPattern.exec(text);
  }

  const versionMatch = text.match(/^%PDF-(\d\.\d)/);
  const javascriptIndicators = [];
  const autoActionIndicators = [];
  const launchIndicators = [];
  const embeddedFileIndicators = [];
  const uriIndicators = [];
  const suspiciousTextIndicators = [];
  const suspiciousTextSnippets = [];
  const embeddedFileNames = [];
  const uriUrls = [];
  const highEntropyStreams = [];
  const decodedPayloadHits = [];
  const validatedPortableExecutables = [];

  let pageCount = 0;
  let streamCount = 0;
  let objectStreamCount = 0;
  let xrefStreamCount = 0;
  let embeddedFileCount = 0;
  let maxStreamEntropy = 0;

  objects.forEach(objectEntry => {
    const objectText = decodePdfNameEscapes(objectEntry.text);
    const objectId = `${objectEntry.number} ${objectEntry.generation}`;
    if (/\/Type\s*\/Page\b/i.test(objectText)) {
      pageCount += 1;
    }
    if (/\/Type\s*\/ObjStm\b/i.test(objectText)) {
      objectStreamCount += 1;
    }
    if (/\/Type\s*\/XRef\b/i.test(objectText)) {
      xrefStreamCount += 1;
    }
    if (/\/JavaScript\b|\/JS\b|app\.launchURL|this\.submitForm|exportDataObject|importDataObject/i.test(objectText)) {
      javascriptIndicators.push(`Object ${objectId} referenced JavaScript-capable content.`);
      suspiciousTextSnippets.push(...collectRegexSnippets(objectText, /(?:\/JavaScript\b|\/JS\b|app\.launchURL|this\.submitForm|exportDataObject|importDataObject)/gi));
    }
    if (/\/OpenAction\b|\/AA\b/i.test(objectText)) {
      autoActionIndicators.push(`Object ${objectId} contained automatic action triggers.`);
      suspiciousTextSnippets.push(...collectRegexSnippets(objectText, /(?:\/OpenAction\b|\/AA\b)/gi));
    }
    if (/\/Launch\b/i.test(objectText)) {
      launchIndicators.push(`Object ${objectId} contained a launch action.`);
      suspiciousTextSnippets.push(...collectRegexSnippets(objectText, /\/Launch\b/gi));
    }
    if (/\/EmbeddedFiles\b|\/EmbeddedFile\b|\/Type\s*\/Filespec\b/i.test(objectText)) {
      embeddedFileIndicators.push(`Object ${objectId} referenced embedded file structures.`);
      embeddedFileCount += 1;
    }
    if (/\/URI\b|https?:\/\//i.test(objectText)) {
      uriIndicators.push(`Object ${objectId} referenced an external URI.`);
    }
    if (/\/SubmitForm\b|\/GoToR\b|\/RichMedia\b/i.test(objectText)) {
      suspiciousTextIndicators.push(`Object ${objectId} used remote or active PDF actions.`);
      suspiciousTextSnippets.push(...collectRegexSnippets(objectText, /(?:\/SubmitForm\b|\/GoToR\b|\/RichMedia\b)/gi));
    }

    embeddedFileNames.push(...extractPdfNames(objectText));
    uriUrls.push(...extractPdfUris(objectText));

    const streamPattern = /stream\r?\n/g;
    let streamMatch = streamPattern.exec(objectEntry.text);
    while (streamMatch) {
      streamCount += 1;
      const streamStart = objectEntry.start + streamMatch.index + streamMatch[0].length;
      const streamEnd = text.indexOf('endstream', streamStart);
      if (streamEnd === -1) {
        break;
      }
      const streamBytes = buffer.subarray(streamStart, streamEnd);
      const entropy = Number(computeEntropy(streamBytes).toFixed(3));
      maxStreamEntropy = Math.max(maxStreamEntropy, entropy);
      if (entropy >= 7.5) {
        highEntropyStreams.push(`Object ${objectId} stream (${streamBytes.length} bytes, entropy ${entropy.toFixed(3)})`);
      }

      decodedPayloadHits.push(...detectEmbeddedPayloadSignatures(streamBytes, streamStart));
      validatedPortableExecutables.push(
        ...detectEmbeddedPayloadSignatures(streamBytes, streamStart)
          .filter(hit => hit.type === 'portable-executable' && hit.validated)
      );

      if (/\/FlateDecode\b/i.test(objectText)) {
        const decoded = safeInflatePdfStream(streamBytes);
        if (decoded) {
          const decodedText = decoded.toString('latin1');
          const decodedHits = detectEmbeddedPayloadSignatures(decoded, streamStart);
          decodedPayloadHits.push(...decodedHits);
          validatedPortableExecutables.push(...decodedHits.filter(hit => hit.type === 'portable-executable' && hit.validated));
          inspectDecodedPdfText(decodedText, {
            javascriptIndicators,
            autoActionIndicators,
            launchIndicators,
            embeddedFileIndicators,
            uriIndicators,
            suspiciousTextIndicators,
            suspiciousTextSnippets,
          });
        }
      }
      streamMatch = streamPattern.exec(objectEntry.text);
    }
  });

  const suspiciousIndicators = toUniqueList([
    ...(javascriptIndicators.length > 0 ? ['embedded-javascript'] : []),
    ...(autoActionIndicators.length > 0 ? ['automatic-actions'] : []),
    ...(launchIndicators.length > 0 ? ['launch-actions'] : []),
    ...(embeddedFileCount > 0 || embeddedFileNames.length > 0 ? ['embedded-files'] : []),
    ...(uriIndicators.length > 0 || uriUrls.length > 0 ? ['external-uris'] : []),
    ...(highEntropyStreams.length > 0 ? ['high-entropy-streams'] : []),
    ...(decodedPayloadHits.length > 0 ? ['embedded-payload-signatures'] : []),
    ...(validatedPortableExecutables.length > 0 ? ['validated-embedded-pe'] : []),
    ...suspiciousTextIndicators,
  ]);

  return {
    version: versionMatch?.[1] || null,
    objectCount: objects.length,
    pageCount,
    streamCount,
    objectStreamCount,
    xrefStreamCount,
    javascript: {
      present: javascriptIndicators.length > 0,
      count: javascriptIndicators.length,
      indicators: toUniqueList(javascriptIndicators).slice(0, MAX_SNIPPETS),
    },
    autoActions: {
      present: autoActionIndicators.length > 0,
      count: autoActionIndicators.length,
      indicators: toUniqueList(autoActionIndicators).slice(0, MAX_SNIPPETS),
    },
    launchActions: {
      present: launchIndicators.length > 0,
      count: launchIndicators.length,
      indicators: toUniqueList(launchIndicators).slice(0, MAX_SNIPPETS),
    },
    embeddedFiles: {
      present: embeddedFileCount > 0 || embeddedFileNames.length > 0,
      count: Math.max(embeddedFileCount, embeddedFileNames.length),
      names: toUniqueList(embeddedFileNames).slice(0, MAX_NAMES),
      indicators: toUniqueList(embeddedFileIndicators).slice(0, MAX_SNIPPETS),
    },
    uriActions: {
      present: uriIndicators.length > 0 || uriUrls.length > 0,
      count: Math.max(uriIndicators.length, uriUrls.length),
      indicators: toUniqueList(uriIndicators).slice(0, MAX_SNIPPETS),
      urls: toUniqueList(uriUrls).slice(0, MAX_URLS),
    },
    streamEntropy: {
      highEntropyStreamCount: highEntropyStreams.length,
      maxEntropy: Number(maxStreamEntropy.toFixed(3)),
      suspiciousStreams: highEntropyStreams.slice(0, MAX_SNIPPETS),
    },
    embeddedPayloads: {
      present: decodedPayloadHits.length > 0,
      count: decodedPayloadHits.length,
      hits: decodedPayloadHits.slice(0, MAX_SNIPPETS),
    },
    validatedPortableExecutables: {
      present: validatedPortableExecutables.length > 0,
      count: validatedPortableExecutables.length,
      hits: validatedPortableExecutables.slice(0, MAX_SNIPPETS),
    },
    suspiciousIndicators,
    suspiciousTextSnippets: toUniqueList(suspiciousTextSnippets).slice(0, MAX_SNIPPETS),
  };
};
