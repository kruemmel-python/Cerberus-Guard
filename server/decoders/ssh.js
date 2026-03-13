import { hasPort, payloadToUtf8 } from './helpers.js';

export const sshDecoder = {
  id: 'SSH',
  matches(packet) {
    return hasPort(packet, [22]);
  },
  decode(packet) {
    const payloadText = payloadToUtf8(packet.payloadBuffer);
    const firstLine = payloadText.split('\n')[0]?.trim() ?? '';
    if (!firstLine.startsWith('SSH-')) {
      return null;
    }

    const bannerParts = firstLine.split('-');
    const versionPart = bannerParts[1] ?? '';
    const softwarePart = bannerParts.slice(2).join('-');

    return {
      l7Protocol: 'SSH',
      l7Metadata: {
        sshBanner: firstLine,
        sshVersion: versionPart,
        sshSoftware: softwarePart,
      },
    };
  },
};
