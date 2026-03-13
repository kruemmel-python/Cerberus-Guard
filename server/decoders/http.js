import { HTTP_METHODS, hasPort, payloadToUtf8 } from './helpers.js';

export const httpDecoder = {
  id: 'HTTP',
  matches(packet) {
    return hasPort(packet, [80, 8080, 8000]);
  },
  decode(packet) {
    const payloadText = payloadToUtf8(packet.payloadBuffer);
    if (!payloadText) {
      return null;
    }

    const firstLine = payloadText.split('\r\n')[0] ?? '';
    const isHttp = HTTP_METHODS.some(method => firstLine.startsWith(`${method} `)) || firstLine.startsWith('HTTP/');
    if (!isHttp) {
      return null;
    }

    const hostMatch = payloadText.match(/^Host:\s*(.+)$/im);
    const userAgentMatch = payloadText.match(/^User-Agent:\s*(.+)$/im);
    const contentTypeMatch = payloadText.match(/^Content-Type:\s*(.+)$/im);
    const authHeaderMatch = payloadText.match(/^Authorization:\s*(.+)$/im);
    const firstLineParts = firstLine.split(' ');

    return {
      l7Protocol: 'HTTP',
      l7Metadata: {
        method: firstLineParts[0] || '',
        path: firstLineParts[1] || '',
        host: hostMatch?.[1]?.trim() || '',
        userAgent: userAgentMatch?.[1]?.trim() || '',
        contentType: contentTypeMatch?.[1]?.trim() || '',
        authorization: authHeaderMatch?.[1]?.trim() || '',
      },
    };
  },
};
