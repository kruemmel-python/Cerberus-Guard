import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { analyzeWithCerberusLab, refreshCerberusLabLlmReview } from './cerberusLabService.js';
import {
  deleteSandboxAnalysesByIds,
  getLatestSandboxAnalysisBySha256,
  listStalePendingSandboxAnalyses,
  upsertSandboxAnalysis,
} from './db.js';

const MAX_SANDBOX_FILE_SIZE_BYTES = 100 * 1024 * 1024;
const STALE_PENDING_ANALYSIS_GRACE_SECONDS = 30;

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

const normalizeUploadFileName = value => {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const normalizedName = path.basename(value.trim());
  return normalizedName || null;
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

const shouldReuseExistingCerberusAnalysis = (configuration, metadata = {}) => {
  if (configuration?.sandboxProvider !== 'cerberus_lab') {
    return true;
  }

  if (configuration?.sandboxDynamicExecutionEnabled) {
    return false;
  }

  if (Array.isArray(metadata.sidecarFiles) && metadata.sidecarFiles.length > 0) {
    return false;
  }

  return true;
};

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
  constructor({ onLog, onAnalysisUpdate } = {}) {
    this.onLog = onLog;
    this.onAnalysisUpdate = onAnalysisUpdate;
    this.configuration = null;
    this.inFlight = new Map();
    this.inFlightAnalysisIds = new Set();
  }

  configure(configuration) {
    this.configuration = configuration;
    this.pruneStaleAnalyses();
  }

  log(level, message, details) {
    if (this.onLog) {
      this.onLog(level, message, details);
    }
  }

  emitAnalysisUpdate(analysis) {
    if (this.onAnalysisUpdate) {
      this.onAnalysisUpdate(analysis);
    }
  }

  getActiveAnalysisCount() {
    return this.inFlight.size;
  }

  hasActiveAnalyses() {
    return this.getActiveAnalysisCount() > 0;
  }

  persistAnalysis(analysis) {
    const persistedAnalysis = upsertSandboxAnalysis({
      ...analysis,
      stage: analysis.stage ?? analysis.status,
      stageMessage: analysis.stageMessage ?? null,
    });
    this.emitAnalysisUpdate(persistedAnalysis);
    return persistedAnalysis;
  }

  async refreshExistingAnalysis(existingAnalysis, options = {}) {
    if (!existingAnalysis || existingAnalysis.provider !== 'cerberus_lab' || existingAnalysis.status !== 'completed') {
      return existingAnalysis;
    }

    const refreshedAnalysis = await refreshCerberusLabLlmReview({
      analysis: existingAnalysis,
      configuration: this.configuration,
      force: options.force === true,
    });

    if (refreshedAnalysis !== existingAnalysis) {
      return this.persistAnalysis(refreshedAnalysis);
    }

    return existingAnalysis;
  }

  getStalePendingCutoff(sensorId = null) {
    const timeoutSeconds = Math.max(Number(this.configuration?.sandboxTimeoutSeconds) || 300, 30);
    return {
      sensorId,
      updatedBefore: new Date(Date.now() - (timeoutSeconds + STALE_PENDING_ANALYSIS_GRACE_SECONDS) * 1000).toISOString(),
    };
  }

  pruneStaleAnalyses({ sensorId = null } = {}) {
    if (!this.configuration) {
      return 0;
    }

    const { updatedBefore } = this.getStalePendingCutoff(sensorId);
    const staleAnalyses = listStalePendingSandboxAnalyses(updatedBefore, sensorId)
      .filter(analysis => !this.inFlightAnalysisIds.has(analysis.id));

    if (staleAnalyses.length === 0) {
      return 0;
    }

    const deletedCount = deleteSandboxAnalysesByIds(staleAnalyses.map(analysis => analysis.id));
    if (deletedCount > 0) {
      this.log('INFO', 'Removed stale sandbox analyses.', {
        deletedCount,
        updatedBefore,
        sensorId,
      });
    }

    return deletedCount;
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

  assertConfigured({ requireEnabled = true } = {}) {
    if (requireEnabled && !this.configuration?.sandboxEnabled) {
      throw new Error('Sandbox integration is disabled.');
    }

    if (!this.configuration) {
      throw new Error('Sandbox service is not configured.');
    }

    if (this.configuration.sandboxProvider === 'none') {
      throw new Error('Sandbox provider is disabled.');
    }

    if (!['cape', 'cerberus_lab'].includes(this.configuration.sandboxProvider)) {
      throw new Error(`Unsupported sandbox provider: ${this.configuration.sandboxProvider}`);
    }

    if (this.configuration.sandboxProvider === 'cape' && !this.configuration.sandboxBaseUrl.trim()) {
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

  async analyzeFile(filePath, metadata = {}, options = {}) {
    this.assertConfigured({
      requireEnabled: options.requireEnabled ?? true,
    });

    this.pruneStaleAnalyses();

    const fileInfo = await ensureAbsoluteFilePath(filePath);
    const effectiveFileInfo = {
      ...fileInfo,
      fileName: normalizeUploadFileName(metadata.fileName) || fileInfo.fileName,
    };
    const { buffer, sha256 } = await hashFileSha256(fileInfo.filePath);
    const allowExistingAnalysisReuse = shouldReuseExistingCerberusAnalysis(this.configuration, metadata);
    const existingAnalysis = allowExistingAnalysisReuse
      ? getLatestSandboxAnalysisBySha256(sha256, this.configuration.sandboxProvider, { includeRaw: true })
      : null;
    if (existingAnalysis && ['queued', 'running', 'completed'].includes(existingAnalysis.status)) {
      return this.refreshExistingAnalysis(existingAnalysis);
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
      stage: 'queued',
      stageMessage: 'Queued for sandbox submission.',
      provider: this.configuration.sandboxProvider,
      verdict: 'unknown',
      summary: 'Queued for sandbox submission.',
      score: null,
      filePath: effectiveFileInfo.filePath,
      fileName: effectiveFileInfo.fileName,
      fileSize: effectiveFileInfo.fileSize,
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
      this.inFlightAnalysisIds.add(baseAnalysis.id);
      let persistedAnalysis = this.persistAnalysis(baseAnalysis);

      try {
        let score = null;
        let signatures = [];
        let verdict = 'unknown';
        let summary = 'Sandbox analysis completed.';
        let raw = null;
        let externalTaskId = null;

        if (this.configuration.sandboxProvider === 'cape') {
          persistedAnalysis = this.persistAnalysis({
            ...persistedAnalysis,
            updatedAt: new Date().toISOString(),
            status: 'running',
            stage: 'submitting',
            stageMessage: 'Submitting sample to CAPE.',
            summary: 'Submitting sample to CAPE.',
          });

          const taskId = await this.submitCapeFile(effectiveFileInfo, buffer);
          persistedAnalysis = this.persistAnalysis({
            ...persistedAnalysis,
            updatedAt: new Date().toISOString(),
            status: 'running',
            stage: 'waiting_for_report',
            stageMessage: `Waiting for CAPE report (task ${taskId}).`,
            summary: `Submitted to CAPE task ${taskId}.`,
            externalTaskId: taskId,
          });

          const report = await this.waitForCapeReport(taskId);
          score = extractScore(report);
          signatures = extractSignatures(report);
          verdict = determineVerdict(score, signatures);
          summary = buildSummary(verdict, score, signatures, report);
          raw = report;
          externalTaskId = taskId;
        } else {
          persistedAnalysis = this.persistAnalysis({
            ...persistedAnalysis,
            updatedAt: new Date().toISOString(),
            status: 'running',
            stage: 'static_analysis',
            stageMessage: 'Running static reverse analysis in Cerberus Lab.',
            summary: 'Running local reverse analysis in Cerberus Lab.',
          });

          const report = await analyzeWithCerberusLab({
            configuration: this.configuration,
            fileInfo: effectiveFileInfo,
            fileBuffer: buffer,
            sha256,
            metadata: {
              ...metadata,
              onLog: (level, message, details) => {
                this.log(level, message, details);
              },
              onStageUpdate: (stage, stageMessage) => {
                persistedAnalysis = this.persistAnalysis({
                  ...persistedAnalysis,
                  updatedAt: new Date().toISOString(),
                  status: 'running',
                  stage,
                  stageMessage,
                  summary: stageMessage || persistedAnalysis.summary,
                });
              },
            },
          });
          score = report.score;
          signatures = report.signatures;
          verdict = report.verdict;
          summary = report.summary;
          raw = report.raw;
        }

        const completedAnalysis = this.persistAnalysis({
          ...persistedAnalysis,
          updatedAt: new Date().toISOString(),
          status: 'completed',
          stage: 'completed',
          stageMessage: 'Sandbox analysis completed.',
          verdict,
          score,
          summary,
          reportUrl: null,
          errorMessage: null,
          externalTaskId,
          signatures,
          raw,
        });

        this.log('INFO', 'Sandbox analysis completed.', {
          filePath: fileInfo.filePath,
          sha256,
          verdict,
          score,
          provider: this.configuration.sandboxProvider,
          taskId: externalTaskId,
        });

        return completedAnalysis;
      } catch (error) {
        const failedAnalysis = this.persistAnalysis({
          ...persistedAnalysis,
          updatedAt: new Date().toISOString(),
          status: 'failed',
          stage: 'failed',
          stageMessage: error instanceof Error ? error.message : 'Sandbox analysis failed.',
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
      this.inFlightAnalysisIds.delete(baseAnalysis.id);
    });

    this.inFlight.set(inFlightKey, analysisPromise);
    return analysisPromise;
  }
}
