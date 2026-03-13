import { hasPort } from './helpers.js';

const SMB2_COMMANDS = {
  0x0000: 'NEGOTIATE',
  0x0001: 'SESSION_SETUP',
  0x0003: 'TREE_CONNECT',
  0x0005: 'CREATE',
  0x0008: 'READ',
  0x0009: 'WRITE',
  0x000b: 'IOCTL',
};

const SMB1_COMMANDS = {
  0x72: 'NEGOTIATE',
  0x73: 'SESSION_SETUP',
  0x75: 'TREE_CONNECT',
  0xa2: 'NT_CREATE',
  0x25: 'TRANS',
};

export const smbDecoder = {
  id: 'SMB',
  matches(packet) {
    return hasPort(packet, [139, 445]);
  },
  decode(packet) {
    const payload = packet.payloadBuffer;
    if (payload.length < 8) {
      return null;
    }

    if (payload[0] === 0xfe && payload.subarray(1, 4).toString('ascii') === 'SMB') {
      const commandCode = payload.readUInt16LE(12);
      return {
        l7Protocol: 'SMB',
        l7Metadata: {
          smbDialect: 'SMB2',
          smbCommand: SMB2_COMMANDS[commandCode] ?? `0x${commandCode.toString(16)}`,
        },
      };
    }

    if (payload[0] === 0xff && payload.subarray(1, 4).toString('ascii') === 'SMB') {
      const commandCode = payload[4];
      return {
        l7Protocol: 'SMB',
        l7Metadata: {
          smbDialect: 'SMB1',
          smbCommand: SMB1_COMMANDS[commandCode] ?? `0x${commandCode.toString(16)}`,
        },
      };
    }

    return null;
  },
};
