import { hasPort } from './helpers.js';

const decodeUtf8 = (buffer) => {
  try {
    return buffer.toString('utf8').replace(/\0/g, ' ').trim();
  } catch {
    return '';
  }
};

const detectMySql = (payload) => {
  if (payload.length > 5 && payload[4] === 0x03) {
    return {
      engine: 'MySQL',
      operation: 'COM_QUERY',
      query: decodeUtf8(payload.subarray(5, 64)),
    };
  }
  return null;
};

const detectPostgres = (payload) => {
  if (payload.length > 6 && payload[0] === 0x51) {
    return {
      engine: 'PostgreSQL',
      operation: 'QUERY',
      query: decodeUtf8(payload.subarray(5, 64)),
    };
  }

  if (payload.length >= 8) {
    const version = payload.readUInt32BE(4);
    if (version === 0x00030000) {
      return {
        engine: 'PostgreSQL',
        operation: 'STARTUP',
        query: '',
      };
    }
  }

  return null;
};

const detectMssql = (payload) => {
  if (payload.length < 8) {
    return null;
  }

  const typeMap = {
    0x01: 'SQL_BATCH',
    0x10: 'LOGIN',
    0x12: 'PRELOGIN',
  };
  const packetType = payload[0];
  if (!typeMap[packetType]) {
    return null;
  }

  return {
    engine: 'MSSQL',
    operation: typeMap[packetType],
    query: '',
  };
};

export const sqlDecoder = {
  id: 'SQL',
  matches(packet) {
    return hasPort(packet, [1433, 3306, 5432]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    const detected = detectMySql(payload) ?? detectPostgres(payload) ?? detectMssql(payload);
    if (!detected) {
      return null;
    }

    return {
      l7Protocol: 'SQL',
      l7Metadata: {
        sqlEngine: detected.engine,
        sqlOperation: detected.operation,
        sqlQuerySnippet: detected.query,
      },
    };
  },
};
