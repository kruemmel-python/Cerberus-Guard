import { dnsDecoder } from './dns.js';
import { ftpDecoder } from './ftp.js';
import { httpDecoder } from './http.js';
import { rdpDecoder } from './rdp.js';
import { smbDecoder } from './smb.js';
import { sqlDecoder } from './sql.js';
import { sshDecoder } from './ssh.js';
import { tlsDecoder } from './tls.js';

const fallbackResult = {
  l7Protocol: 'UNKNOWN',
  l7Metadata: {},
};

const DECODER_ORDER = [dnsDecoder, httpDecoder, tlsDecoder, sshDecoder, ftpDecoder, smbDecoder, rdpDecoder, sqlDecoder];

export const detectLayer7Metadata = (packet) => {
  if (!packet.payloadBuffer || packet.payloadBuffer.length === 0) {
    return fallbackResult;
  }

  for (const decoder of DECODER_ORDER) {
    if (!decoder.matches(packet)) {
      continue;
    }

    const result = decoder.decode(packet);
    if (result) {
      return result;
    }
  }

  const fallbackHttp = httpDecoder.decode(packet);
  return fallbackHttp ?? fallbackResult;
};
