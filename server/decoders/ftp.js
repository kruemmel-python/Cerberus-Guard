import { hasPort, payloadToUtf8 } from './helpers.js';

const FTP_COMMANDS = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'CWD', 'QUIT', 'AUTH', 'PORT', 'PASV', 'EPSV'];

export const ftpDecoder = {
  id: 'FTP',
  matches(packet) {
    return hasPort(packet, [21]);
  },
  decode(packet) {
    const payloadText = payloadToUtf8(packet.payloadBuffer);
    const firstLine = payloadText.split('\r\n')[0]?.trim() ?? '';
    if (!firstLine) {
      return null;
    }

    const command = firstLine.split(' ')[0] ?? '';
    const isCommand = FTP_COMMANDS.includes(command);
    const isStatus = /^\d{3}\b/.test(command);
    if (!isCommand && !isStatus) {
      return null;
    }

    return {
      l7Protocol: 'FTP',
      l7Metadata: {
        ftpCommand: isCommand ? command : '',
        ftpStatus: isStatus ? command : '',
        ftpMessage: firstLine.slice(command.length).trim(),
      },
    };
  },
};
