import { hasPort } from './helpers.js';

const TLS_VERSIONS = {
  0x0301: 'TLS1.0',
  0x0302: 'TLS1.1',
  0x0303: 'TLS1.2',
  0x0304: 'TLS1.3',
};

export const tlsDecoder = {
  id: 'TLS',
  matches(packet) {
    return hasPort(packet, [443, 8443]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    if (payload.length < 43 || payload[0] !== 0x16) {
      return null;
    }

    const recordLength = payload.readUInt16BE(3);
    const version = payload.readUInt16BE(1);
    if (payload.length < 5 + recordLength || payload[5] !== 0x01) {
      return null;
    }

    let cursor = 9;
    cursor += 2;
    cursor += 32;
    if (cursor >= payload.length) {
      return null;
    }

    const sessionIdLength = payload[cursor];
    cursor += 1 + sessionIdLength;
    if (cursor + 2 > payload.length) {
      return null;
    }

    const cipherSuiteLength = payload.readUInt16BE(cursor);
    cursor += 2 + cipherSuiteLength;
    if (cursor >= payload.length) {
      return null;
    }

    const compressionLength = payload[cursor];
    cursor += 1 + compressionLength;
    if (cursor + 2 > payload.length) {
      return null;
    }

    const extensionsLength = payload.readUInt16BE(cursor);
    cursor += 2;
    const extensionsEnd = cursor + extensionsLength;
    let sni = '';

    while (cursor + 4 <= extensionsEnd && cursor + 4 <= payload.length) {
      const extensionType = payload.readUInt16BE(cursor);
      const extensionLength = payload.readUInt16BE(cursor + 2);
      cursor += 4;

      if (extensionType === 0x0000 && cursor + 2 <= payload.length) {
        const serverNameListLength = payload.readUInt16BE(cursor);
        let serverCursor = cursor + 2;
        const serverNameListEnd = serverCursor + serverNameListLength;

        while (serverCursor + 3 <= serverNameListEnd && serverCursor + 3 <= payload.length) {
          const nameType = payload[serverCursor];
          const nameLength = payload.readUInt16BE(serverCursor + 1);
          serverCursor += 3;
          if (nameType === 0x00) {
            sni = payload.subarray(serverCursor, serverCursor + nameLength).toString('utf8');
            break;
          }
          serverCursor += nameLength;
        }
      }

      cursor += extensionLength;
    }

    return {
      l7Protocol: 'TLS',
      l7Metadata: {
        sni,
        tlsVersion: TLS_VERSIONS[version] ?? `0x${version.toString(16)}`,
      },
    };
  },
};
