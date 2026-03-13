export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'];

export const payloadToUtf8 = (payload) => {
  try {
    return payload.toString('utf8');
  } catch {
    return '';
  }
};

export const getAsciiLine = (payload) => payloadToUtf8(payload).split('\r\n')[0] ?? '';

export const hasPort = (packet, ports) => ports.includes(packet.destinationPort) || ports.includes(packet.sourcePort);

export const parseDnsName = (payload, startOffset) => {
  const labels = [];
  let cursor = startOffset;

  while (cursor < payload.length) {
    const length = payload[cursor];
    if (length === 0) {
      return {
        name: labels.join('.'),
        nextOffset: cursor + 1,
      };
    }

    if ((length & 0xc0) === 0xc0) {
      return null;
    }

    cursor += 1;
    labels.push(payload.subarray(cursor, cursor + length).toString('utf8'));
    cursor += length;
  }

  return null;
};
