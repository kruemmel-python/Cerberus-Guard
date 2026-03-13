import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { getLatestSandboxAnalysisBySha256, upsertSandboxAnalysis } from './db.js';

const MAX_SANDBOX_FILE_SIZE_BYTES = 100 * 1024 * 1024;

const sleep = ms => new Promise(resolve => {
  setTimeout(resolve, ms);
});

const normalizeBaseUrl = baseUrl => baseUrl.trim().replace(/\/+$/, '');

const ensureAbsoluteFilePath = async targetPath => {
  const resolvedPath = path.resolve(targetPath);
  if (!path.isAbsolute(resolvedPath)) {
    throw new Error('Sandbox analysis requires an absolute local file path.');
  }

  const stat = await fs.stat(resolvedPath);
  if (!stat.isFile()) {
    throw new Error('Sandbox analysis only supports local files.');
  }

  if (stat.size > MAX_SANDBOX_FILE_SIZE_BYTES) {
    throw new Error(`Sandbox upload limit exceeded (${MAX_SANDBOX_FILE_SIZE_BYTES} bytes).`);
  }

  return {
    filePath: resolvedPath,
    fileName: path.basename(resolvedPath),
    fileSize: stat.size,
  };
};

const hashFileSha256 = async targetPath => {
  const fileBuffer = await fs.readFile(targetPath);
  return {
    buffer: fileBuffer,
    sha256: crypto.createHash('sha256').update(fileBuffer).digest('hex'),
  };
};

const toNumber = value => {
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
};

const uniqueStrings = values => [...new Set(values.filter(Boolean).map(value => String(value).trim()).filter(Boolean))];

const parseCapeTaskId = payload => {
  const directTaskId = payload?.task_id ?? payload?.taskId ?? payload?.data?.task_id ?? payload?.data?.taskId;
  if (directTaskId) {
    return String(directTaskId);
  }

  if (Array.isArray(payload?.task_ids) && payload.task_ids.length > 0) {
    return String(payload.task_ids[0]);
  }

  if (Array.isArray(payload?.data?.task_ids) && payload.data.task_ids.length > 0) {
    return String(payload.data.task_ids[0]);
  }

  throw new Error('Sandbox submission did not return a task identifier.');
};

const extractScore = report => {
  const candidates = [
    report?.info?.score,
    report?.malscore,
    report?.mal_score,
    report?.statistics?.malscore,
    report?.target?.file?.score,
  ];

  for (const candidate of candidates) {
    const numericCandidate = toNumber(candidate);
    if (numericCandidate !== null) {
      return numericCandidate;
    }
  }

  return null;
};

const extractSignatures = report => uniqueStrings([
  ...(Array.isArray(report?.signatures) ? report.signatures.flatMap(signature => [signature?.name, signature?.description]) : []),
  ...(Array.isArray(report?.ttps) ? report.ttps.map(ttp => ttp?.signature) : []),
]);

const determineVerdict = (score, signatures) => {
  if (score !== null) {
    if (score >= 7) {
      return 'malicious';
    }
    if (score >= 3) {
      return 'suspicious';
    }
    return 'clean';
  }

  if (signatures.length > 0) {
    return 'suspicious';
  }

  return 'unknown';
};

const buildSummary = (verdict, score, signatures, report) => {
  const targetType = report?.target?.file?.type || report?.target?.file?.guest_paths?.[0] || report?.target?.category;
  const signatureSummary = signatures.length > 0 ? `${signatures.slice(0, 3).join(', ')}${signatures.length > 3 ? '...' : ''}` : 'no signatures';
  const scoreSummary = score !== null ? `score ${score.toFixed(1)}` : 'no score';
  return `${verdict.toUpperCase()} via CAPE (${scoreSummary}, ${signatureSummary}${targetType ? `, ${targetType}` : ''}).`;
};

export class SandboxService {
  constructor({ onLog } = {}) {
    this.onLog = onLog;
    this.configuration = null;
    this.inFlight = new Map();
  }

  configure(configuration) {
    this.configuration = configuration;
  }

  log(level, message, details) {
    if (this.onLog) {
      this.onLog(level, message, details);
    }
  }

  buildAuthHeaders() {
    const apiKey = this.configuration?.sandboxApiKey?.trim();
    if (!apiKey) {
      return {};
    }

    return {
      Authorization: apiKey.includes(' ') ? apiKey : `Token ${apiKey}`,
    };
  }

  assertConfigured() {
    if (!this.configuration?.sandboxEnabled) {
      throw new Error('Sandbox integration is disabled.');
    }

    if (this.configuration.sandboxProvider !== 'cape') {
      throw new Error(`Unsupported sandbox provider: ${this.configuration.sandboxProvider}`);
    }

    if (!this.configuration.sandboxBaseUrl.trim()) {
      throw new Error('Sandbox base URL is not configured.');
    }
  }

  async fetchJson(url, init) {
    const response = await fetch(url, init);
    const rawText = await response.text();
    let payload = {};

    if (rawText) {
      try {
        payload = JSON.parse(rawText);
      } catch {
        payload = { message: rawText };
      }
    }

    if (!response.ok) {
      throw new Error(payload?.error || payload?.message || `Sandbox request failed with status ${response.status}.`);
    }

    return payload;
  }

  async submitCapeFile(fileInfo, fileBuffer) {
    const endpoint = `${normalizeBaseUrl(this.configuration.sandboxBaseUrl)}/apiv2/tasks/create/file/`;
    const formData = new FormData();
    formData.append('file', new Blob([fileBuffer]), fileInfo.fileName);

    const payload = await this.fetchJson(endpoint, {
      method: 'POST',
      headers: this.buildAuthHeaders(),
      body: formData,
    });

    return parseCapeTaskId(payload);
  }

  async getCapeTaskStatus(taskId) {
    const endpoint = `${normalizeBaseUrl(this.configuration.sandboxBaseUrl)}/apiv2/tasks/view/${encodeURIComponent(taskId)}/`;
    return this.fetchJson(endpoint, {
      headers: this.buildAuthHeaders(),
    });
  }

  async getCapeTaskReport(taskId) {
    const endpoint = `${normalizeBaseUrl(this.configuration.sandboxBaseUrl)}/apiv2/tasks/get/report/${encodeURIComponent(taskId)}/`;
    return this.fetchJson(endpoint, {
      headers: this.buildAuthHeaders(),
    });
  }

  async waitForCapeReport(taskId) {
    const timeoutAt = Date.now() + this.configuration.sandboxTimeoutSeconds * 1000;

    while (Date.now() < timeoutAt) {
      const statusPayload = await this.getCapeTaskStatus(taskId);
      const status = String(
        statusPayload?.task?.status
        ?? statusPayload?.data?.status
        ?? statusPayload?.status
        ?? ''
      ).toLowerCase();

      if (['reported', 'completed', 'finished', 'success'].includes(status)) {
        return this.getCapeTaskReport(taskId);
      }

      if (['failed', 'error', 'broken', 'terminated'].includes(status)) {
        throw new Error(`Sandbox task ${taskId} failed with status "${status}".`);
      }

      await sleep(this.configuration.sandboxPollingIntervalMs);
    }

    throw new Error(`Sandbox task ${taskId} timed out after ${this.configuration.sandboxTimeoutSeconds} seconds.`);
  }

  async analyzeFile(filePath, metadata = {}) {
    this.assertConfigured();

    const fileInfo = await ensureAbsoluteFilePath(filePath);
    const { buffer, sha256 } = await hashFileSha256(fileInfo.filePath);
    const existingAnalysis = getLatestSandboxAnalysisBySha256(sha256, this.configuration.sandboxProvider);
    if (existingAnalysis && ['queued', 'running', 'completed'].includes(existingAnalysis.status)) {
      return existingAnalysis;
    }

    const inFlightKey = `${this.configuration.sandboxProvider}:${sha256}`;
    if (this.inFlight.has(inFlightKey)) {
      return this.inFlight.get(inFlightKey);
    }

    const createdAt = new Date().toISOString();
    const baseAnalysis = {
      id: crypto.randomUUID(),
      createdAt,
      updatedAt: createdAt,
      status: 'queued',
      provider: this.configuration.sandboxProvider,
      verdict: 'unknown',
      summary: 'Queued for sandbox submission.',
      score: null,
      filePath: fileInfo.filePath,
      fileName: fileInfo.fileName,
      fileSize: fileInfo.fileSize,
      sha256,
      processName: metadata.processName ?? null,
      trafficEventId: metadata.trafficEventId ?? null,
      externalTaskId: null,
      reportUrl: null,
      errorMessage: null,
      signatures: [],
      sensorId: metadata.sensorId ?? 'unknown',
      sensorName: metadata.sensorName ?? 'Unknown Sensor',
      raw: null,
    };

    const analysisPromise = (async () => {
      let persistedAnalysis = upsertSandboxAnalysis(baseAnalysis);

      try {
        const taskId = await this.submitCapeFile(fileInfo, buffer);
        persistedAnalysis = upsertSandboxAnalysis({
          ...persistedAnalysis,
          updatedAt: new Date().toISOString(),
          status: 'running',
          summary: `Submitted to CAPE task ${taskId}.`,
          externalTaskId: taskId,
        });

        const report = await this.waitForCapeReport(taskId);
        const score = extractScore(report);
        const signatures = extractSignatures(report);
        const verdict = determineVerdict(score, signatures);
        const completedAnalysis = upsertSandboxAnalysis({
          ...persistedAnalysis,
          updatedAt: new Date().toISOString(),
          status: 'completed',
          verdict,
          score,
          summary: buildSummary(verdict, score, signatures, report),
          reportUrl: null,
          errorMessage: null,
          signatures,
          raw: report,
        });

        this.log('INFO', 'Sandbox analysis completed.', {
          filePath: fileInfo.filePath,
          sha256,
          verdict,
          score,
          taskId,
        });

        return completedAnalysis;
      } catch (error) {
        const failedAnalysis = upsertSandboxAnalysis({
          ...persistedAnalysis,
          updatedAt: new Date().toISOString(),
          status: 'failed',
          verdict: 'unknown',
          summary: 'Sandbox analysis failed.',
          errorMessage: error instanceof Error ? error.message : 'Sandbox analysis failed.',
          signatures: persistedAnalysis.signatures ?? [],
          raw: null,
        });

        this.log('ERROR', 'Sandbox analysis failed.', {
          filePath: fileInfo.filePath,
          sha256,
          error: error instanceof Error ? error.message : 'Sandbox analysis failed.',
        });

        throw Object.assign(new Error(failedAnalysis.errorMessage), {
          analysis: failedAnalysis,
        });
      }
    })().finally(() => {
      this.inFlight.delete(inFlightKey);
    });

    this.inFlight.set(inFlightKey, analysisPromise);
    return analysisPromise;
  }
}
