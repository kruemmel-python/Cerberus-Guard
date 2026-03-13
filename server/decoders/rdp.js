import { hasPort, payloadToUtf8 } from './helpers.js';

const X224_TYPES = {
  0xe0: 'connection_request',
  0xd0: 'connection_confirm',
  0xf0: 'data',
};

export const rdpDecoder = {
  id: 'RDP',
  matches(packet) {
    return hasPort(packet, [3389]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    if (payload.length < 7 || payload[0] !== 0x03 || payload[1] !== 0x00) {
      return null;
    }

    const payloadText = payloadToUtf8(payload);
    const cookieMatch = payloadText.match(/Cookie:\s*mstshash=([^\r\n]+)/i);
    const x224Type = payload.length > 5 ? X224_TYPES[payload[5]] ?? `0x${payload[5].toString(16)}` : '';

    return {
      l7Protocol: 'RDP',
      l7Metadata: {
        rdpCookie: cookieMatch?.[1]?.trim() || '',
        rdpX224Type: x224Type,
      },
    };
  },
};
