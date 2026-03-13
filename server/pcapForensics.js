import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import pcapWriterModule from 'pcap-writer';
import pcapParserModule from 'pcap-parser';
import { directories } from './db.js';
import { decodePacketFrame } from './captureAgent.js';

const { createPcapWriter } = pcapWriterModule;
const { parse: parsePcap } = pcapParserModule;
const PCAP_LINKTYPE_ETHERNET = 1;

const wait = (durationMs) => new Promise(resolve => setTimeout(resolve, durationMs));

export class PcapForensics {
  constructor() {
    this.recentFrames = [];
  }

  reset() {
    this.recentFrames = [];
  }

  rememberFrame(frameRecord, maxFrames) {
    this.recentFrames.push(frameRecord);
    if (this.recentFrames.length > maxFrames) {
      this.recentFrames.shift();
    }
  }

  async exportThreatWindow({ packetCount, attackType, sourceIp, explanation, threatEventId }) {
    const exportFrames = this.recentFrames.slice(-packetCount);
    if (exportFrames.length === 0) {
      return null;
    }

    const artifactId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const safeSourceIp = sourceIp.replace(/[:.]/g, '_');
    const fileName = `${createdAt.replace(/[:.]/g, '-')}_${safeSourceIp}_${attackType}.pcap`;
    const filePath = path.join(directories.pcapDirectory, fileName);
    const writer = createPcapWriter(filePath, 65535, PCAP_LINKTYPE_ETHERNET);

    await new Promise((resolve, reject) => {
      try {
        exportFrames.forEach(frame => {
          writer.writePacket(frame.rawFrame, frame.timestampMicros);
        });
        writer.close(() => resolve(null));
      } catch (error) {
        reject(error);
      }
    });

    const stats = fs.statSync(filePath);
    return {
      id: artifactId,
      createdAt,
      fileName,
      filePath,
      attackType,
      sourceIp,
      packetCount: exportFrames.length,
      explanation,
      bytes: stats.size,
      threatEventId,
    };
  }

  async parseReplayFile(filePath) {
    return new Promise((resolve, reject) => {
      const packets = [];
      let linkLayerType = PCAP_LINKTYPE_ETHERNET;
      const parser = parsePcap(filePath);

      parser.on('globalHeader', header => {
        linkLayerType = header.linkLayerType;
      });

      parser.on('packet', packet => {
        packets.push({
          timestampMicros: packet.header.timestampSeconds * 1_000_000 + packet.header.timestampMicroseconds,
          originalLength: packet.header.originalLength,
          rawFrame: packet.data,
          linkLayerType,
        });
      });

      parser.on('end', () => resolve(packets));
      parser.on('error', reject);
    });
  }

  async replayPcap({ filePath, fileName, speedMultiplier = 10, onStatus, onPacket }) {
    const replayPackets = await this.parseReplayFile(filePath);
    const safeSpeed = speedMultiplier > 0 ? speedMultiplier : 10;

    onStatus({
      state: 'running',
      fileName,
      processedPackets: 0,
      totalPackets: replayPackets.length,
      startedAt: new Date().toISOString(),
      completedAt: null,
      message: null,
    });

    let previousTimestamp = replayPackets[0]?.timestampMicros ?? 0;
    for (let index = 0; index < replayPackets.length; index += 1) {
      const replayPacket = replayPackets[index];
      const delayMs = Math.min(Math.max((replayPacket.timestampMicros - previousTimestamp) / 1000 / safeSpeed, 0), 500);
      previousTimestamp = replayPacket.timestampMicros;
      if (delayMs > 0) {
        await wait(delayMs);
      }

      const decodedPacket = decodePacketFrame({
        frame: replayPacket.rawFrame,
        linkType: replayPacket.linkLayerType === PCAP_LINKTYPE_ETHERNET ? 'ETHERNET' : 'UNKNOWN',
        captureDevice: `replay:${fileName}`,
        timestamp: new Date(replayPacket.timestampMicros / 1000).toISOString(),
      });

      if (decodedPacket) {
        await onPacket(decodedPacket);
      }

      onStatus({
        state: 'running',
        fileName,
        processedPackets: index + 1,
        totalPackets: replayPackets.length,
        startedAt: null,
        completedAt: null,
        message: null,
      });
    }

    onStatus({
      state: 'completed',
      fileName,
      processedPackets: replayPackets.length,
      totalPackets: replayPackets.length,
      startedAt: null,
      completedAt: new Date().toISOString(),
      message: null,
    });
  }
}
