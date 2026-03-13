import os from 'node:os';
import { randomUUID } from 'node:crypto';
import dgram from 'node:dgram';
import capModule from 'cap';
import { detectLayer7Metadata } from './decoders/index.js';

const { Cap, decoders } = capModule;
const { PROTOCOL } = decoders;

const PACKET_BUFFER_SIZE = 65535;
const LIBPCAP_BUFFER_SIZE = 10 * 1024 * 1024;
const MAX_PAYLOAD_SNIPPET_BYTES = 64;
const PRIMARY_ADDRESS_TIMEOUT_MS = 750;
const DEVICE_DEPRIORITIZATION_PATTERNS = [
  /loopback/i,
  /hyper-v/i,
  /wan miniport/i,
  /wi-fi direct/i,
  /bluetooth/i,
  /virtual/i,
  /npcap loopback/i,
];
const DEVICE_PREFERENCE_PATTERNS = [
  /wi-?fi/i,
  /\bwlan\b/i,
  /ethernet/i,
  /mediatek/i,
  /intel/i,
  /realtek/i,
];

const isLinkLocalAddress = (address) =>
  address.startsWith('169.254.') || address.startsWith('fe80:');

const isPreferredIpv4Address = (address) =>
  /^\d+\.\d+\.\d+\.\d+$/.test(address)
  && !address.startsWith('127.')
  && !address.startsWith('169.254.');

const getLocalAddresses = () =>
  new Set(
    Object.values(os.networkInterfaces())
      .flat()
      .filter(Boolean)
      .map(addressInfo => addressInfo.address)
  );

const bufferToHex = (buffer) => buffer.toString('hex');

const normalizeDevice = (device) => ({
  name: device.name,
  description: device.description || device.name,
  addresses: Array.isArray(device.addresses) ? device.addresses.map(address => address.addr).filter(Boolean) : [],
  loopback: typeof device.flags === 'string' ? device.flags.includes('LOOPBACK') : false,
});

const getAddressCandidates = () => {
  const candidates = [];

  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const addressInfo of addresses ?? []) {
      if (!addressInfo || addressInfo.internal) {
        continue;
      }

      if (addressInfo.family === 'IPv4' && isPreferredIpv4Address(addressInfo.address)) {
        candidates.push(addressInfo.address);
      }
    }
  }

  return [...new Set(candidates)];
};

const scoreDevice = (device, primaryAddress, addressCandidates) => {
  const descriptor = `${device.description} ${device.name}`.toLowerCase();
  const deviceAddresses = new Set(device.addresses.map(address => address.toLowerCase()));
  let score = 0;

  if (primaryAddress && deviceAddresses.has(primaryAddress.toLowerCase())) {
    score += 500;
  }

  for (const candidate of addressCandidates) {
    if (deviceAddresses.has(candidate.toLowerCase())) {
      score += 150;
    }
  }

  if (device.addresses.some(isPreferredIpv4Address)) {
    score += 80;
  }

  if (device.addresses.some(address => isLinkLocalAddress(address.toLowerCase()))) {
    score -= 40;
  }

  if (device.loopback) {
    score -= 250;
  }

  if (DEVICE_PREFERENCE_PATTERNS.some(pattern => pattern.test(descriptor))) {
    score += 60;
  }

  if (DEVICE_DEPRIORITIZATION_PATTERNS.some(pattern => pattern.test(descriptor))) {
    score -= 150;
  }

  return score;
};

const sortDevicesByPreference = (devices, primaryAddress = null) => {
  const addressCandidates = getAddressCandidates();
  return [...devices].sort((leftDevice, rightDevice) => {
    const scoreDelta = scoreDevice(rightDevice, primaryAddress, addressCandidates) - scoreDevice(leftDevice, primaryAddress, addressCandidates);
    if (scoreDelta !== 0) {
      return scoreDelta;
    }
    return leftDevice.description.localeCompare(rightDevice.description);
  });
};

const resolvePrimaryOutboundAddress = async () => {
  const socket = dgram.createSocket('udp4');

  try {
    const connected = await Promise.race([
      new Promise((resolve, reject) => {
        socket.once('error', reject);
        socket.connect(53, '1.1.1.1', resolve);
      }),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Timed out while resolving primary network interface.')), PRIMARY_ADDRESS_TIMEOUT_MS);
      }),
    ]);

    if (connected === undefined) {
      const localSocket = socket.address();
      if (typeof localSocket === 'object' && isPreferredIpv4Address(localSocket.address)) {
        return localSocket.address;
      }
    }
  } catch {
    return null;
  } finally {
    try {
      socket.close();
    } catch {
      // ignore socket close errors during interface probing
    }
  }

  return null;
};

const resolveCaptureDevice = async (preferredDeviceName) => {
  if (preferredDeviceName) {
    return preferredDeviceName;
  }

  const primaryAddress = await resolvePrimaryOutboundAddress();
  if (primaryAddress) {
    try {
      const deviceForPrimaryAddress = Cap.findDevice(primaryAddress);
      if (deviceForPrimaryAddress) {
        return deviceForPrimaryAddress;
      }
    } catch {
      // fall through to heuristic device selection
    }
  }

  const sortedDevices = sortDevicesByPreference(Cap.deviceList().map(normalizeDevice), primaryAddress);
  const [bestDevice] = sortedDevices;
  if (bestDevice?.name) {
    return bestDevice.name;
  }

  return Cap.findDevice();
};

const getDirection = (localAddresses, sourceIp, destinationIp) => {
  if (localAddresses.has(sourceIp)) {
    return 'OUTBOUND';
  }

  if (localAddresses.has(destinationIp)) {
    return 'INBOUND';
  }

  return 'UNKNOWN';
};

const buildPacketFromTransport = ({ basePacket, transportPacket, sourcePort, destinationPort, protocol }) => {
  const payloadBuffer = transportPacket;
  const payloadSnippet = payloadBuffer.subarray(0, MAX_PAYLOAD_SNIPPET_BYTES);
  const packetWithPayload = {
    ...basePacket,
    sourcePort,
    destinationPort,
    protocol,
    payloadSnippet: bufferToHex(payloadSnippet),
    payloadBuffer,
  };
  const l7 = detectLayer7Metadata(packetWithPayload);

  return {
    packet: {
      ...basePacket,
      sourcePort,
      destinationPort,
      protocol,
      payloadSnippet: bufferToHex(payloadSnippet),
      l7Protocol: l7.l7Protocol,
      l7Metadata: l7.l7Metadata,
    },
    rawFrame: transportPacket.__rawFrame ?? null,
  };
};

export const decodePacketFrame = ({
  frame,
  linkType = 'ETHERNET',
  captureDevice = 'unknown',
  timestamp = new Date().toISOString(),
  localAddresses = getLocalAddresses(),
}) => {
  if (linkType !== 'ETHERNET') {
    return null;
  }

  const ethernet = decoders.Ethernet(frame);
  if (ethernet.info.type !== PROTOCOL.ETHERNET.IPV4) {
    return null;
  }

  const ipv4 = decoders.IPV4(frame, ethernet.offset);
  const basePacket = {
    id: randomUUID(),
    sourceIp: ipv4.info.srcaddr,
    destinationIp: ipv4.info.dstaddr,
    timestamp,
    captureDevice,
    size: frame.length,
    direction: getDirection(localAddresses, ipv4.info.srcaddr, ipv4.info.dstaddr),
  };

  if (ipv4.info.protocol === PROTOCOL.IP.TCP) {
    const tcp = decoders.TCP(frame, ipv4.offset);
    const payloadBuffer = frame.subarray(tcp.offset);
    payloadBuffer.__rawFrame = frame;
    const packet = buildPacketFromTransport({
      basePacket,
      transportPacket: payloadBuffer,
      sourcePort: tcp.info.srcport,
      destinationPort: tcp.info.dstport,
      protocol: 'TCP',
    });
    return {
      packet: packet.packet,
      rawFrame: frame,
      originalLength: frame.length,
    };
  }

  if (ipv4.info.protocol === PROTOCOL.IP.UDP) {
    const udp = decoders.UDP(frame, ipv4.offset);
    const payloadBuffer = frame.subarray(udp.offset);
    payloadBuffer.__rawFrame = frame;
    const packet = buildPacketFromTransport({
      basePacket,
      transportPacket: payloadBuffer,
      sourcePort: udp.info.srcport,
      destinationPort: udp.info.dstport,
      protocol: 'UDP',
    });
    return {
      packet: packet.packet,
      rawFrame: frame,
      originalLength: frame.length,
    };
  }

  return null;
};

export class CaptureAgent {
  constructor({ onPacket, onStatus, onError }) {
    this.onPacket = onPacket;
    this.onStatus = onStatus;
    this.onError = onError;
    this.capture = null;
    this.buffer = null;
    this.linkType = null;
    this.activeDevice = null;
    this.activeFilter = '';
    this.startedAt = null;
    this.replayActive = false;
    this.localAddresses = getLocalAddresses();
  }

  listInterfaces() {
    try {
      return sortDevicesByPreference(Cap.deviceList().map(normalizeDevice));
    } catch (error) {
      this.onError(error instanceof Error ? error : new Error('Failed to enumerate capture devices.'));
      return [];
    }
  }

  getStatus(clientCount = 0) {
    return {
      running: Boolean(this.capture),
      activeDevice: this.activeDevice,
      activeFilter: this.activeFilter,
      startedAt: this.startedAt,
      clientCount,
      replayActive: this.replayActive,
    };
  }

  setReplayActive(active, clientCount = 0) {
    this.replayActive = active;
    this.onStatus(this.getStatus(clientCount));
  }

  async start({ deviceName, filter }, clientCount = 0) {
    this.stop(clientCount, false);

    this.localAddresses = getLocalAddresses();

    const selectedDevice = await resolveCaptureDevice(deviceName);
    if (!selectedDevice) {
      throw new Error('No compatible capture device found. Install Npcap/WinPcap compatibility on Windows or libpcap on Linux.');
    }

    this.capture = new Cap();
    this.buffer = Buffer.alloc(PACKET_BUFFER_SIZE);
    this.activeDevice = selectedDevice;
    this.activeFilter = filter;
    this.startedAt = new Date().toISOString();

    this.linkType = this.capture.open(selectedDevice, filter, LIBPCAP_BUFFER_SIZE, this.buffer);
    if (typeof this.capture.setMinBytes === 'function') {
      this.capture.setMinBytes(0);
    }

    this.capture.on('packet', nbytes => {
      try {
        const frame = Buffer.from(this.buffer.subarray(0, nbytes));
        const decodedPacket = decodePacketFrame({
          frame,
          linkType: this.linkType,
          captureDevice: this.activeDevice || 'unknown',
          timestamp: new Date().toISOString(),
          localAddresses: this.localAddresses,
        });

        if (decodedPacket) {
          this.onPacket(decodedPacket);
        }
      } catch (error) {
        this.onError(error instanceof Error ? error : new Error('Failed to decode captured packet.'));
      }
    });

    this.onStatus(this.getStatus(clientCount));
    return this.getStatus(clientCount);
  }

  stop(clientCount = 0, emitStatus = true) {
    if (this.capture) {
      this.capture.close();
      this.capture = null;
    }

    this.buffer = null;
    this.linkType = null;
    this.activeDevice = null;
    this.activeFilter = '';
    this.startedAt = null;

    if (emitStatus) {
      this.onStatus(this.getStatus(clientCount));
    }

    return this.getStatus(clientCount);
  }
}
