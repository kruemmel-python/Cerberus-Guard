import path from 'node:path';
import zlib from 'node:zlib';

const ZIP_LOCAL_FILE_HEADER = 0x04034b50;
const ZIP_CENTRAL_DIRECTORY_HEADER = 0x02014b50;
const ZIP_END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const OLE_HEADER = Buffer.from('d0cf11e0a1b11ae1', 'hex');

const OOXML_EXTENSIONS = new Set(['.docx', '.docm', '.dotx', '.dotm', '.xlsx', '.xlsm', '.xltx', '.xltm', '.xlam', '.pptx', '.pptm', '.potx', '.potm', '.ppsx', '.ppsm']);
const OLE_EXTENSIONS = new Set(['.doc', '.xls', '.ppt']);
const RTF_EXTENSIONS = new Set(['.rtf']);

const toUniqueList = values => [...new Set(values.filter(Boolean).map(value => String(value).trim()).filter(Boolean))];

const sanitizeSnippet = value => String(value || '').replace(/\s+/g, ' ').trim();

const readAsciiStrings = (buffer, minLength = 4) => {
  const results = [];
  let current = [];

  for (const value of buffer) {
    if (value >= 32 && value <= 126) {
      current.push(value);
      continue;
    }
    if (current.length >= minLength) {
      results.push(Buffer.from(current).toString('ascii'));
    }
    current = [];
  }

  if (current.length >= minLength) {
    results.push(Buffer.from(current).toString('ascii'));
  }

  return results;
};

const readUtf16Strings = (buffer, minLength = 4) => {
  const results = [];
  let current = '';

  for (let index = 0; index + 1 < buffer.length; index += 2) {
    const low = buffer[index];
    const high = buffer[index + 1];
    if (high === 0 && low >= 32 && low <= 126) {
      current += String.fromCharCode(low);
      continue;
    }
    if (current.length >= minLength) {
      results.push(current);
    }
    current = '';
  }

  if (current.length >= minLength) {
    results.push(current);
  }

  return results;
};

const parseZipEntries = buffer => {
  const searchStart = Math.max(0, buffer.length - 0x10000 - 22);
  let eocdOffset = -1;
  for (let offset = buffer.length - 22; offset >= searchStart; offset -= 1) {
    if (buffer.readUInt32LE(offset) === ZIP_END_OF_CENTRAL_DIRECTORY) {
      eocdOffset = offset;
      break;
    }
  }

  if (eocdOffset === -1) {
    return [];
  }

  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);
  const entries = [];
  let offset = centralDirectoryOffset;

  for (let index = 0; index < totalEntries && offset + 46 <= buffer.length; index += 1) {
    if (buffer.readUInt32LE(offset) !== ZIP_CENTRAL_DIRECTORY_HEADER) {
      break;
    }

    const flags = buffer.readUInt16LE(offset + 8);
    const compression = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const fileName = buffer.subarray(offset + 46, offset + 46 + fileNameLength).toString('utf8');

    entries.push({
      fileName,
      flags,
      compression,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
    });

    offset += 46 + fileNameLength + extraLength + commentLength;
  }

  return entries;
};

const extractZipEntryData = (buffer, entry) => {
  if (!entry || (entry.flags & 0x1) !== 0) {
    return null;
  }
  if (entry.localHeaderOffset + 30 > buffer.length || buffer.readUInt32LE(entry.localHeaderOffset) !== ZIP_LOCAL_FILE_HEADER) {
    return null;
  }

  const fileNameLength = buffer.readUInt16LE(entry.localHeaderOffset + 26);
  const extraLength = buffer.readUInt16LE(entry.localHeaderOffset + 28);
  const dataStart = entry.localHeaderOffset + 30 + fileNameLength + extraLength;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > buffer.length) {
    return null;
  }

  const compressed = buffer.subarray(dataStart, dataEnd);
  if (entry.compression === 0) {
    return compressed;
  }
  if (entry.compression === 8) {
    try {
      return zlib.inflateRawSync(compressed);
    } catch {
      return null;
    }
  }

  return null;
};

const extractUrls = text => toUniqueList(text.match(/https?:\/\/[^\s"'<>]+/gi) || []).slice(0, 20);

const detectOoxmlSubtype = entryNames => {
  if (entryNames.some(name => name.startsWith('word/'))) {
    return 'word';
  }
  if (entryNames.some(name => name.startsWith('xl/'))) {
    return 'excel';
  }
  if (entryNames.some(name => name.startsWith('ppt/'))) {
    return 'powerpoint';
  }
  return 'ooxml';
};

const normalizeOfficeDescription = ({ format, subtype, extension }) => {
  if (format === 'rtf') {
    return 'Rich Text Format document';
  }
  if (format === 'ole') {
    switch (extension) {
      case '.doc':
        return 'Legacy Microsoft Word document';
      case '.xls':
        return 'Legacy Microsoft Excel workbook';
      case '.ppt':
        return 'Legacy Microsoft PowerPoint presentation';
      default:
        return 'Legacy OLE compound document';
    }
  }

  switch (subtype) {
    case 'word':
      return 'Microsoft Word OOXML document';
    case 'excel':
      return 'Microsoft Excel OOXML workbook';
    case 'powerpoint':
      return 'Microsoft PowerPoint OOXML presentation';
    default:
      return 'OOXML office document';
  }
};

const analyzeOoxmlDocument = ({ filePath, buffer }) => {
  const extension = path.extname(filePath).toLowerCase();
  const entries = parseZipEntries(buffer);
  const entryNames = entries.map(entry => entry.fileName);
  const subtype = detectOoxmlSubtype(entryNames);
  const macroEntries = entries.filter(entry => /vbaProject\.bin$/i.test(entry.fileName));
  const activeXEntries = entries.filter(entry => /activeX\//i.test(entry.fileName));
  const embeddedEntries = entries.filter(entry => /(embeddings\/|oleObject|package\.bin$)/i.test(entry.fileName));
  const customUiEntries = entries.filter(entry => /customUI\//i.test(entry.fileName));
  const relationshipEntries = entries.filter(entry => /\.rels$/i.test(entry.fileName));
  const externalTargets = [];
  const relationshipIndicators = [];
  const macroAutoExecIndicators = [];
  const macroExecutionIndicators = [];
  const ddeIndicators = [];
  const urls = [];

  relationshipEntries.forEach(entry => {
    const data = extractZipEntryData(buffer, entry);
    if (!data) {
      return;
    }
    const text = data.toString('utf8').replace(/\u0000/g, '');
    urls.push(...extractUrls(text));

    const externalPattern = /Target="([^"]+)"[^>]*TargetMode="External"/gi;
    let externalMatch = externalPattern.exec(text);
    while (externalMatch) {
      externalTargets.push(externalMatch[1]);
      externalMatch = externalPattern.exec(text);
    }

    if (/(attachedTemplate|externalLink|oleObject|hyperlink|package)/i.test(text)) {
      relationshipIndicators.push(entry.fileName);
    }
  });

  macroEntries.forEach(entry => {
    const data = extractZipEntryData(buffer, entry);
    if (!data) {
      return;
    }
    const strings = toUniqueList([...readAsciiStrings(data), ...readUtf16Strings(data)]);
    strings.forEach(value => {
      if (/(AutoOpen|Auto_Open|Document_Open|Workbook_Open|Presentation_Open|AutoClose|Document_Close)/i.test(value)) {
        macroAutoExecIndicators.push(sanitizeSnippet(value).slice(0, 180));
      }
      if (/(Shell|CreateObject|WScript\.Shell|PowerShell|cmd\.exe|URLDownloadToFile|XMLHTTP|WinHttpRequest|MSXML2\.XMLHTTP)/i.test(value)) {
        macroExecutionIndicators.push(sanitizeSnippet(value).slice(0, 180));
      }
      if (/DDEAUTO|INCLUDEPICTURE|INCLUDETEXT/i.test(value)) {
        ddeIndicators.push(sanitizeSnippet(value).slice(0, 180));
      }
      urls.push(...extractUrls(value));
    });
  });

  entries
    .filter(entry => /\.(?:xml|rels)$/i.test(entry.fileName))
    .slice(0, 80)
    .forEach(entry => {
      const data = extractZipEntryData(buffer, entry);
      if (!data) {
        return;
      }
      const text = data.toString('utf8').replace(/\u0000/g, '');
      urls.push(...extractUrls(text));
      if (/DDEAUTO|INCLUDEPICTURE|INCLUDETEXT/i.test(text)) {
        ddeIndicators.push(`${entry.fileName}: ${sanitizeSnippet(text.match(/(?:DDEAUTO|INCLUDEPICTURE|INCLUDETEXT)[^<]{0,120}/i)?.[0] || 'DDE-like field').slice(0, 180)}`);
      }
    });

  const suspiciousIndicators = toUniqueList([
    ...(macroEntries.length > 0 ? ['macro-project'] : []),
    ...(macroAutoExecIndicators.length > 0 ? ['autoexec-macro'] : []),
    ...(macroExecutionIndicators.length > 0 ? ['macro-execution-surface'] : []),
    ...(embeddedEntries.length > 0 ? ['embedded-objects'] : []),
    ...(activeXEntries.length > 0 ? ['activex-controls'] : []),
    ...(externalTargets.length > 0 ? ['external-relationships'] : []),
    ...(ddeIndicators.length > 0 ? ['dde-fields'] : []),
    ...(customUiEntries.length > 0 ? ['custom-ui'] : []),
  ]);

  return {
    format: 'ooxml',
    subtype,
    description: normalizeOfficeDescription({ format: 'ooxml', subtype, extension }),
    entryCount: entries.length,
    macroProject: {
      present: macroEntries.length > 0,
      entries: macroEntries.map(entry => entry.fileName).slice(0, 12),
      autoExecIndicators: toUniqueList(macroAutoExecIndicators).slice(0, 12),
      executionIndicators: toUniqueList(macroExecutionIndicators).slice(0, 12),
    },
    embeddedObjects: {
      present: embeddedEntries.length > 0,
      count: embeddedEntries.length,
      entries: embeddedEntries.map(entry => entry.fileName).slice(0, 12),
    },
    activeX: {
      present: activeXEntries.length > 0,
      entries: activeXEntries.map(entry => entry.fileName).slice(0, 12),
    },
    externalRelationships: {
      present: externalTargets.length > 0,
      count: externalTargets.length,
      targets: toUniqueList(externalTargets).slice(0, 12),
      relationshipEntries: toUniqueList(relationshipIndicators).slice(0, 12),
    },
    dde: {
      present: ddeIndicators.length > 0,
      indicators: toUniqueList(ddeIndicators).slice(0, 12),
    },
    customUiEntries: customUiEntries.map(entry => entry.fileName).slice(0, 12),
    urls: toUniqueList(urls).slice(0, 20),
    suspiciousIndicators,
  };
};

const analyzeOleDocument = ({ filePath, buffer, strings }) => {
  const extension = path.extname(filePath).toLowerCase();
  const combinedStrings = toUniqueList(strings.length > 0 ? strings : [...readAsciiStrings(buffer), ...readUtf16Strings(buffer)]);
  const subtype = extension === '.doc'
    ? 'word'
    : extension === '.xls'
      ? 'excel'
      : extension === '.ppt'
        ? 'powerpoint'
        : 'ole';

  const macroIndicators = combinedStrings.filter(value => /(VBA|Macros|PROJECT|dir|AutoOpen|Document_Open|Workbook_Open|Presentation_Open)/i.test(value));
  const executionIndicators = combinedStrings.filter(value => /(Shell|CreateObject|WScript\.Shell|PowerShell|cmd\.exe|URLDownloadToFile|XMLHTTP|WinHttpRequest)/i.test(value));
  const embeddedObjectIndicators = combinedStrings.filter(value => /(ObjectPool|Ole10Native|Equation\.3|Package|CompObj|MSHTML)/i.test(value));
  const ddeIndicators = combinedStrings.filter(value => /(DDEAUTO|INCLUDEPICTURE|INCLUDETEXT)/i.test(value));
  const urls = toUniqueList(combinedStrings.flatMap(extractUrls)).slice(0, 20);

  return {
    format: 'ole',
    subtype,
    description: normalizeOfficeDescription({ format: 'ole', subtype, extension }),
    entryCount: null,
    macroProject: {
      present: macroIndicators.length > 0,
      entries: [],
      autoExecIndicators: toUniqueList(macroIndicators).slice(0, 12),
      executionIndicators: toUniqueList(executionIndicators).slice(0, 12),
    },
    embeddedObjects: {
      present: embeddedObjectIndicators.length > 0,
      count: embeddedObjectIndicators.length,
      entries: toUniqueList(embeddedObjectIndicators).slice(0, 12),
    },
    activeX: {
      present: combinedStrings.some(value => /ActiveX/i.test(value)),
      entries: toUniqueList(combinedStrings.filter(value => /ActiveX/i.test(value))).slice(0, 12),
    },
    externalRelationships: {
      present: urls.length > 0,
      count: urls.length,
      targets: urls,
      relationshipEntries: [],
    },
    dde: {
      present: ddeIndicators.length > 0,
      indicators: toUniqueList(ddeIndicators).slice(0, 12),
    },
    customUiEntries: [],
    urls,
    suspiciousIndicators: toUniqueList([
      ...(macroIndicators.length > 0 ? ['macro-project'] : []),
      ...(executionIndicators.length > 0 ? ['macro-execution-surface'] : []),
      ...(embeddedObjectIndicators.length > 0 ? ['embedded-objects'] : []),
      ...(ddeIndicators.length > 0 ? ['dde-fields'] : []),
    ]),
  };
};

const analyzeRtfDocument = ({ filePath, buffer }) => {
  const extension = path.extname(filePath).toLowerCase();
  const text = buffer.toString('latin1').replace(/\u0000/g, '');
  const objectClassMatches = [];
  const objectClassPattern = /\\objclass\s+([^\s\\{}]+)/gi;
  let objectClassMatch = objectClassPattern.exec(text);
  while (objectClassMatch) {
    objectClassMatches.push(objectClassMatch[1]);
    objectClassMatch = objectClassPattern.exec(text);
  }

  const ddeIndicators = toUniqueList((text.match(/(?:DDEAUTO|INCLUDEPICTURE|INCLUDETEXT)[^\\]{0,160}/gi) || []).map(sanitizeSnippet)).slice(0, 12);
  const embeddedObjectIndicators = toUniqueList((text.match(/(?:\\object|\\objdata|\\objupdate|\\bin\d+)/gi) || []).map(sanitizeSnippet)).slice(0, 12);
  const externalReferences = extractUrls(text);

  return {
    format: 'rtf',
    subtype: extension.replace(/^\./, '') || 'rtf',
    description: normalizeOfficeDescription({ format: 'rtf', subtype: 'rtf', extension }),
    entryCount: null,
    macroProject: {
      present: false,
      entries: [],
      autoExecIndicators: [],
      executionIndicators: [],
    },
    embeddedObjects: {
      present: embeddedObjectIndicators.length > 0 || objectClassMatches.length > 0,
      count: embeddedObjectIndicators.length || objectClassMatches.length,
      entries: toUniqueList([...embeddedObjectIndicators, ...objectClassMatches]).slice(0, 12),
    },
    activeX: {
      present: /ActiveX/i.test(text),
      entries: toUniqueList((text.match(/ActiveX[^\\]{0,120}/gi) || []).map(sanitizeSnippet)).slice(0, 12),
    },
    externalRelationships: {
      present: externalReferences.length > 0,
      count: externalReferences.length,
      targets: externalReferences,
      relationshipEntries: [],
    },
    dde: {
      present: ddeIndicators.length > 0,
      indicators: ddeIndicators,
    },
    customUiEntries: [],
    urls: externalReferences,
    suspiciousIndicators: toUniqueList([
      ...(embeddedObjectIndicators.length > 0 || objectClassMatches.length > 0 ? ['embedded-objects'] : []),
      ...(ddeIndicators.length > 0 ? ['dde-fields'] : []),
      ...(/\\objclass\s+Equation\.3/i.test(text) ? ['equation-editor-object'] : []),
    ]),
  };
};

export const detectOfficeContainer = (filePath, buffer) => {
  const extension = path.extname(filePath).toLowerCase();
  const rtfPrefix = buffer.subarray(0, 16).toString('latin1');

  if (RTF_EXTENSIONS.has(extension) || rtfPrefix.startsWith('{\\rtf')) {
    return {
      family: 'office-document',
      format: 'rtf',
      description: 'Rich Text Format document',
      subtype: 'rtf',
    };
  }
  if (buffer.subarray(0, OLE_HEADER.length).equals(OLE_HEADER) || OLE_EXTENSIONS.has(extension)) {
    return {
      family: 'office-document',
      format: 'ole',
      description: normalizeOfficeDescription({ format: 'ole', subtype: 'ole', extension }),
      subtype: extension.replace(/^\./, '') || 'ole',
    };
  }
  if (OOXML_EXTENSIONS.has(extension) || (
    buffer.subarray(0, 4).toString('hex') === '504b0304'
    && buffer.includes(Buffer.from('[Content_Types].xml'))
    && (buffer.includes(Buffer.from('word/')) || buffer.includes(Buffer.from('xl/')) || buffer.includes(Buffer.from('ppt/')))
  )) {
    return {
      family: 'office-document',
      format: 'ooxml',
      description: 'OOXML office document',
      subtype: extension.replace(/^\./, '') || 'ooxml',
    };
  }

  return null;
};

export const analyzeOfficeDocument = ({ filePath, buffer, strings = [] }) => {
  const descriptor = detectOfficeContainer(filePath, buffer);
  if (!descriptor) {
    return null;
  }

  switch (descriptor.format) {
    case 'ooxml':
      return analyzeOoxmlDocument({ filePath, buffer });
    case 'ole':
      return analyzeOleDocument({ filePath, buffer, strings });
    case 'rtf':
      return analyzeRtfDocument({ filePath, buffer });
    default:
      return null;
  }
};
