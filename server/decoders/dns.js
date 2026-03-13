import { hasPort, parseDnsName } from './helpers.js';

export const dnsDecoder = {
  id: 'DNS',
  matches(packet) {
    return hasPort(packet, [53]);
  },
  decode(packet) {
    const dnsPayload = packet.protocol === 'TCP' ? packet.payloadBuffer.subarray(2) : packet.payloadBuffer;
    if (dnsPayload.length < 12) {
      return null;
    }

    const flags = dnsPayload.readUInt16BE(2);
    const questionCount = dnsPayload.readUInt16BE(4);
    const isResponse = Boolean(flags & 0x8000);
    if (questionCount < 1 || isResponse) {
      return null;
    }

    const parsedName = parseDnsName(dnsPayload, 12);
    if (!parsedName || parsedName.nextOffset + 4 > dnsPayload.length) {
      return null;
    }

    const recordType = dnsPayload.readUInt16BE(parsedName.nextOffset);
    return {
      l7Protocol: 'DNS',
      l7Metadata: {
        dnsQuery: parsedName.name,
        dnsType: String(recordType),
      },
    };
  },
};
