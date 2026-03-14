import { hasPort, parseDnsName } from './helpers.js';

export const dnsDecoder = {
  id: 'DNS',
  matches(packet) {
    return hasPort(packet, [53, 5353]);
  },
  decode(packet) {
    const dnsPayload = packet.protocol === 'TCP' ? packet.payloadBuffer.subarray(2) : packet.payloadBuffer;
    if (dnsPayload.length < 12) {
      return null;
    }

    const isMdns = packet.destinationPort === 5353 || packet.sourcePort === 5353;
    const flags = dnsPayload.readUInt16BE(2);
    const questionCount = dnsPayload.readUInt16BE(4);
    const answerCount = dnsPayload.readUInt16BE(6);
    const isResponse = Boolean(flags & 0x8000);
    if (questionCount < 1 && answerCount < 1) {
      return null;
    }

    const parsedName = parseDnsName(dnsPayload, 12);
    return {
      l7Protocol: isMdns ? 'MDNS' : 'DNS',
      l7Metadata: {
        dnsQuery: parsedName?.name ?? '',
        dnsType: parsedName && parsedName.nextOffset + 4 <= dnsPayload.length
          ? String(dnsPayload.readUInt16BE(parsedName.nextOffset))
          : '',
        dnsResponse: isResponse ? 'true' : 'false',
        dnsAnswers: String(answerCount),
        dnsQuestions: String(questionCount),
      },
    };
  },
};
