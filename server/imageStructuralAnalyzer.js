import path from 'node:path';
import zlib from 'node:zlib';

const PNG_SIGNATURE = Buffer.from('89504e470d0a1a0a', 'hex');
const JPEG_SOI = Buffer.from('ffd8', 'hex');
const GIF_HEADERS = [Buffer.from('GIF87a', 'ascii'), Buffer.from('GIF89a', 'ascii')];
const BMP_HEADER = Buffer.from('BM', 'ascii');
const WEBP_HEADER = Buffer.from('WEBP', 'ascii');
const RIFF_HEADER = Buffer.from('RIFF', 'ascii');
const TIFF_LE_HEADER = Buffer.from('49492a00', 'hex');
const TIFF_BE_HEADER = Buffer.from('4d4d002a', 'hex');
const ICO_HEADER = Buffer.from('00000100', 'hex');

const PNG_STANDARD_CHUNKS = new Set([
  'IHDR', 'PLTE', 'IDAT', 'IEND', 'tEXt', 'zTXt', 'iTXt', 'pHYs', 'sRGB', 'gAMA', 'cHRM', 'bKGD', 'tIME', 'sBIT', 'sPLT', 'iCCP', 'eXIf', 'tRNS',
]);

const IMAGE_SUSPICIOUS_TEXT_PATTERN = /(?:<script\b|javascript:|onload\s*=|onerror\s*=|foreignObject\b|<iframe\b|<object\b|<embed\b|powershell(?:\.exe)?|cmd\.exe|rundll32|https?:\/\/|data:\s*(?:application|text\/html))/i;
const SVG_ACTIVE_CONTENT_PATTERN = /(?:<script\b|javascript:|on[a-z]+\s*=|foreignObject\b|<iframe\b|<object\b|<embed\b|xlink:href\s*=|href\s*=\s*["'][^"']*https?:\/\/)/gi;

const toUniqueList = values => [...new Set(values.filter(Boolean).map(value => String(value).trim()).filter(Boolean))];

const sanitizeSnippet = value => String(value || '').replace(/\s+/g, ' ').trim();

const detectImageFormat = (filePath, buffer) => {
  const extension = path.extname(filePath).toLowerCase();
  const lowerTextPrefix = buffer.subarray(0, 512).toString('utf8').toLowerCase();

  if (buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    return { format: 'png', description: 'PNG image' };
  }
  if (buffer.subarray(0, 2).equals(JPEG_SOI)) {
    return { format: 'jpeg', description: 'JPEG image' };
  }
  if (GIF_HEADERS.some(header => buffer.subarray(0, header.length).equals(header))) {
    return { format: 'gif', description: 'GIF image' };
  }
  if (buffer.subarray(0, 2).equals(BMP_HEADER)) {
    return { format: 'bmp', description: 'BMP image' };
  }
  if (buffer.subarray(0, 4).equals(RIFF_HEADER) && buffer.subarray(8, 12).equals(WEBP_HEADER)) {
    return { format: 'webp', description: 'WebP image' };
  }
  if (buffer.subarray(0, 4).equals(TIFF_LE_HEADER) || buffer.subarray(0, 4).equals(TIFF_BE_HEADER)) {
    return { format: 'tiff', description: 'TIFF image' };
  }
  if (buffer.subarray(0, 4).equals(ICO_HEADER)) {
    return { format: 'ico', description: 'Windows icon' };
  }
  if (extension === '.svg' || lowerTextPrefix.includes('<svg')) {
    return { format: 'svg', description: 'SVG image' };
  }
  return null;
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
      hits.push({
        type: signature.label,
        offset: offsetBase + index,
      });
      index = buffer.indexOf(signature.pattern, index + 1);
    }
  }
  return hits;
};

const collectSuspiciousMetadata = (entries = []) => {
  const suspiciousIndicators = [];
  const suspiciousExcerpts = [];

  entries.forEach(entry => {
    const text = sanitizeSnippet(entry);
    if (!text || !IMAGE_SUSPICIOUS_TEXT_PATTERN.test(text)) {
      return;
    }
    suspiciousIndicators.push('metadata-active-content');
    suspiciousExcerpts.push(text.slice(0, 220));
  });

  return {
    suspiciousIndicators: toUniqueList(suspiciousIndicators),
    suspiciousExcerpts: toUniqueList(suspiciousExcerpts).slice(0, 8),
  };
};

const parseSvg = buffer => {
  const text = buffer.toString('utf8').replace(/\u0000/g, '');
  const widthMatch = text.match(/\bwidth\s*=\s*["']?(\d+(?:\.\d+)?)/i);
  const heightMatch = text.match(/\bheight\s*=\s*["']?(\d+(?:\.\d+)?)/i);
  const indicators = [];
  const excerpts = [];
  const externalReferences = [];

  let match = SVG_ACTIVE_CONTENT_PATTERN.exec(text);
  while (match) {
    indicators.push(match[0].trim());
    excerpts.push(sanitizeSnippet(text.slice(Math.max(0, match.index - 80), Math.min(text.length, match.index + match[0].length + 120))));
    match = SVG_ACTIVE_CONTENT_PATTERN.exec(text);
  }

  const referencePattern = /\b(?:href|xlink:href)\s*=\s*["']([^"']+)["']/gi;
  let referenceMatch = referencePattern.exec(text);
  while (referenceMatch) {
    const referenceValue = referenceMatch[1].trim();
    if (/^(?:https?:|javascript:|data:)/i.test(referenceValue)) {
      externalReferences.push(referenceValue);
    }
    referenceMatch = referencePattern.exec(text);
  }

  const metadataSummary = collectSuspiciousMetadata([text]);

  return {
    format: 'svg',
    width: widthMatch ? Number.parseInt(widthMatch[1], 10) : null,
    height: heightMatch ? Number.parseInt(heightMatch[1], 10) : null,
    animated: /<animate\b|<set\b/i.test(text),
    metadata: {
      textEntryCount: 1,
      textEntries: [sanitizeSnippet(text.slice(0, 400))],
      exifPresent: false,
      iccProfilePresent: false,
      customChunks: [],
      ...metadataSummary,
    },
    activeContent: {
      present: indicators.length > 0 || externalReferences.length > 0,
      indicators: toUniqueList(indicators).slice(0, 12),
      externalReferences: toUniqueList(externalReferences).slice(0, 12),
      excerpts: toUniqueList(excerpts).slice(0, 8),
    },
    appendedPayload: {
      present: false,
      bytes: 0,
      hits: [],
    },
  };
};

const parsePng = buffer => {
  let offset = 8;
  let width = null;
  let height = null;
  let endOffset = buffer.length;
  const chunkTypes = [];
  const customChunks = [];
  const textEntries = [];
  let exifPresent = false;
  let iccProfilePresent = false;

  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString('ascii');
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.length) {
      break;
    }

    chunkTypes.push(type);
    const chunkData = buffer.subarray(dataStart, dataEnd);
    if (type === 'IHDR' && length >= 8) {
      width = chunkData.readUInt32BE(0);
      height = chunkData.readUInt32BE(4);
    }
    if (type === 'eXIf') {
      exifPresent = true;
    }
    if (type === 'iCCP') {
      iccProfilePresent = true;
    }
    if (!PNG_STANDARD_CHUNKS.has(type)) {
      customChunks.push(type);
    }
    if (type === 'tEXt') {
      textEntries.push(chunkData.toString('latin1').replace(/\u0000/g, ': '));
    }
    if (type === 'iTXt') {
      textEntries.push(chunkData.toString('utf8').replace(/\u0000/g, ' '));
    }
    if (type === 'zTXt') {
      const separatorIndex = chunkData.indexOf(0);
      if (separatorIndex !== -1 && separatorIndex + 2 <= chunkData.length) {
        const keyword = chunkData.subarray(0, separatorIndex).toString('latin1');
        const compressed = chunkData.subarray(separatorIndex + 2);
        try {
          const inflated = zlib.inflateSync(compressed).toString('utf8');
          textEntries.push(`${keyword}: ${inflated}`);
        } catch {
          textEntries.push(`${keyword}: [compressed text chunk could not be decompressed]`);
        }
      }
    }
    if (type === 'IEND') {
      endOffset = dataEnd + 4;
      break;
    }
    offset = dataEnd + 4;
  }

  const trailingBytes = Math.max(0, buffer.length - endOffset);
  const trailingBuffer = trailingBytes > 0 ? buffer.subarray(endOffset) : Buffer.alloc(0);
  const metadataSummary = collectSuspiciousMetadata(textEntries);

  return {
    format: 'png',
    width,
    height,
    animated: null,
    metadata: {
      textEntryCount: textEntries.length,
      textEntries: toUniqueList(textEntries).slice(0, 12),
      exifPresent,
      iccProfilePresent,
      chunkTypes: toUniqueList(chunkTypes).slice(0, 16),
      customChunks: toUniqueList(customChunks).slice(0, 12),
      ...metadataSummary,
    },
    activeContent: {
      present: false,
      indicators: [],
      externalReferences: [],
      excerpts: [],
    },
    appendedPayload: {
      present: trailingBytes > 0,
      bytes: trailingBytes,
      hits: trailingBytes > 0 ? detectEmbeddedPayloadSignatures(trailingBuffer, endOffset).slice(0, 8) : [],
    },
  };
};

const parseJpeg = buffer => {
  let offset = 2;
  let width = null;
  let height = null;
  let endOffset = buffer.length;
  let exifPresent = false;
  const textEntries = [];

  while (offset + 3 < buffer.length) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }

    let markerOffset = offset + 1;
    while (markerOffset < buffer.length && buffer[markerOffset] === 0xff) {
      markerOffset += 1;
    }
    if (markerOffset >= buffer.length) {
      break;
    }

    const marker = buffer[markerOffset];
    offset = markerOffset + 1;

    if (marker === 0xd9) {
      endOffset = offset;
      break;
    }

    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }

    if (offset + 2 > buffer.length) {
      break;
    }

    const segmentLength = buffer.readUInt16BE(offset);
    const dataStart = offset + 2;
    const dataEnd = dataStart + segmentLength - 2;
    if (dataEnd > buffer.length) {
      break;
    }

    const segmentData = buffer.subarray(dataStart, dataEnd);
    if ((marker >= 0xc0 && marker <= 0xc3) && segmentData.length >= 5) {
      height = segmentData.readUInt16BE(1);
      width = segmentData.readUInt16BE(3);
    }
    if (marker === 0xe1 && segmentData.subarray(0, 4).toString('ascii') === 'Exif') {
      exifPresent = true;
    }
    if (marker === 0xfe) {
      textEntries.push(segmentData.toString('latin1'));
    }

    offset = dataEnd;
  }

  const trailingBytes = Math.max(0, buffer.length - endOffset);
  const trailingBuffer = trailingBytes > 0 ? buffer.subarray(endOffset) : Buffer.alloc(0);
  const metadataSummary = collectSuspiciousMetadata(textEntries);

  return {
    format: 'jpeg',
    width,
    height,
    animated: null,
    metadata: {
      textEntryCount: textEntries.length,
      textEntries: toUniqueList(textEntries).slice(0, 12),
      exifPresent,
      iccProfilePresent: false,
      customChunks: [],
      ...metadataSummary,
    },
    activeContent: {
      present: false,
      indicators: [],
      externalReferences: [],
      excerpts: [],
    },
    appendedPayload: {
      present: trailingBytes > 0,
      bytes: trailingBytes,
      hits: trailingBytes > 0 ? detectEmbeddedPayloadSignatures(trailingBuffer, endOffset).slice(0, 8) : [],
    },
  };
};

const parseGif = buffer => {
  const width = buffer.length >= 8 ? buffer.readUInt16LE(6) : null;
  const height = buffer.length >= 10 ? buffer.readUInt16LE(8) : null;
  const trailerIndex = buffer.lastIndexOf(0x3b);
  const endOffset = trailerIndex >= 0 ? trailerIndex + 1 : buffer.length;
  const trailingBytes = Math.max(0, buffer.length - endOffset);
  const trailerBuffer = trailingBytes > 0 ? buffer.subarray(endOffset) : Buffer.alloc(0);

  return {
    format: 'gif',
    width,
    height,
    animated: null,
    metadata: {
      textEntryCount: 0,
      textEntries: [],
      exifPresent: false,
      iccProfilePresent: false,
      customChunks: [],
      suspiciousIndicators: [],
      suspiciousExcerpts: [],
    },
    activeContent: {
      present: false,
      indicators: [],
      externalReferences: [],
      excerpts: [],
    },
    appendedPayload: {
      present: trailingBytes > 0,
      bytes: trailingBytes,
      hits: trailingBytes > 0 ? detectEmbeddedPayloadSignatures(trailerBuffer, endOffset).slice(0, 8) : [],
    },
  };
};

const parseBmp = buffer => {
  const declaredFileSize = buffer.length >= 6 ? buffer.readUInt32LE(2) : buffer.length;
  const width = buffer.length >= 22 ? buffer.readInt32LE(18) : null;
  const height = buffer.length >= 26 ? Math.abs(buffer.readInt32LE(22)) : null;
  const trailingBytes = Math.max(0, buffer.length - declaredFileSize);
  const trailingBuffer = trailingBytes > 0 ? buffer.subarray(declaredFileSize) : Buffer.alloc(0);

  return {
    format: 'bmp',
    width,
    height,
    animated: null,
    metadata: {
      textEntryCount: 0,
      textEntries: [],
      exifPresent: false,
      iccProfilePresent: false,
      customChunks: [],
      suspiciousIndicators: [],
      suspiciousExcerpts: [],
    },
    activeContent: {
      present: false,
      indicators: [],
      externalReferences: [],
      excerpts: [],
    },
    appendedPayload: {
      present: trailingBytes > 0,
      bytes: trailingBytes,
      hits: trailingBytes > 0 ? detectEmbeddedPayloadSignatures(trailingBuffer, declaredFileSize).slice(0, 8) : [],
    },
  };
};

const parseWebp = buffer => {
  const declaredSize = buffer.length >= 8 ? buffer.readUInt32LE(4) + 8 : buffer.length;
  const trailingBytes = Math.max(0, buffer.length - declaredSize);
  const trailingBuffer = trailingBytes > 0 ? buffer.subarray(declaredSize) : Buffer.alloc(0);

  return {
    format: 'webp',
    width: null,
    height: null,
    animated: /ANIM/.test(buffer.subarray(0, Math.min(buffer.length, 128)).toString('ascii')),
    metadata: {
      textEntryCount: 0,
      textEntries: [],
      exifPresent: buffer.includes(Buffer.from('EXIF', 'ascii')),
      iccProfilePresent: buffer.includes(Buffer.from('ICCP', 'ascii')),
      customChunks: [],
      suspiciousIndicators: [],
      suspiciousExcerpts: [],
    },
    activeContent: {
      present: false,
      indicators: [],
      externalReferences: [],
      excerpts: [],
    },
    appendedPayload: {
      present: trailingBytes > 0,
      bytes: trailingBytes,
      hits: trailingBytes > 0 ? detectEmbeddedPayloadSignatures(trailingBuffer, declaredSize).slice(0, 8) : [],
    },
  };
};

const parseIco = buffer => {
  const width = buffer.length >= 7 ? (buffer[6] || 256) : null;
  const height = buffer.length >= 8 ? (buffer[7] || 256) : null;

  return {
    format: 'ico',
    width,
    height,
    animated: null,
    metadata: {
      textEntryCount: 0,
      textEntries: [],
      exifPresent: false,
      iccProfilePresent: false,
      customChunks: [],
      suspiciousIndicators: [],
      suspiciousExcerpts: [],
    },
    activeContent: {
      present: false,
      indicators: [],
      externalReferences: [],
      excerpts: [],
    },
    appendedPayload: {
      present: false,
      bytes: 0,
      hits: [],
    },
  };
};

const parseTiff = buffer => ({
  format: 'tiff',
  width: null,
  height: null,
  animated: null,
  metadata: {
    textEntryCount: 0,
    textEntries: [],
    exifPresent: true,
    iccProfilePresent: false,
    customChunks: [],
    suspiciousIndicators: [],
    suspiciousExcerpts: [],
  },
  activeContent: {
    present: false,
    indicators: [],
    externalReferences: [],
    excerpts: [],
  },
  appendedPayload: {
    present: false,
    bytes: 0,
    hits: [],
  },
});

export const analyzeImageStructure = ({ filePath, buffer }) => {
  const descriptor = detectImageFormat(filePath, buffer);
  if (!descriptor) {
    return null;
  }

  let analysis;
  switch (descriptor.format) {
    case 'svg':
      analysis = parseSvg(buffer);
      break;
    case 'png':
      analysis = parsePng(buffer);
      break;
    case 'jpeg':
      analysis = parseJpeg(buffer);
      break;
    case 'gif':
      analysis = parseGif(buffer);
      break;
    case 'bmp':
      analysis = parseBmp(buffer);
      break;
    case 'webp':
      analysis = parseWebp(buffer);
      break;
    case 'ico':
      analysis = parseIco(buffer);
      break;
    case 'tiff':
      analysis = parseTiff(buffer);
      break;
    default:
      analysis = null;
  }

  if (!analysis) {
    return null;
  }

  return {
    ...analysis,
    description: descriptor.description,
    suspiciousIndicators: toUniqueList([
      ...(analysis.activeContent.present ? ['active-image-content'] : []),
      ...(analysis.appendedPayload.present ? ['appended-payload'] : []),
      ...(analysis.appendedPayload.hits?.length ? ['embedded-payload-signatures'] : []),
      ...(analysis.metadata.suspiciousIndicators || []),
    ]),
  };
};

export const detectImageContainer = detectImageFormat;
