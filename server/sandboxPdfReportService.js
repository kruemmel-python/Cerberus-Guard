import PDFDocument from 'pdfkit';

const formatTimestamp = value => {
  if (!value) {
    return 'n/a';
  }

  try {
    return new Intl.DateTimeFormat('de-DE', {
      dateStyle: 'medium',
      timeStyle: 'medium',
    }).format(new Date(value));
  } catch {
    return String(value);
  }
};

const formatScore = value => (typeof value === 'number' && Number.isFinite(value) ? value.toFixed(1) : 'n/a');

const formatVerdict = verdict => {
  switch (verdict) {
    case 'malicious':
      return 'Malicious';
    case 'suspicious':
      return 'Suspicious';
    case 'clean':
      return 'Clean';
    default:
      return 'Unknown';
  }
};

const formatStatus = status => {
  switch (status) {
    case 'queued':
      return 'Queued';
    case 'running':
      return 'Running';
    case 'completed':
      return 'Completed';
    case 'failed':
      return 'Failed';
    default:
      return String(status ?? 'n/a');
  }
};

const formatBytes = bytes => {
  if (!Number.isFinite(bytes)) {
    return 'n/a';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const sanitizeFileName = value => value.replace(/[^a-zA-Z0-9._-]+/g, '_');

const startSection = (document, title) => {
  document.moveDown(1.25);
  document
    .font('Helvetica-Bold')
    .fontSize(14)
    .fillColor('#0f172a')
    .text(title);
  document
    .moveTo(document.page.margins.left, document.y + 4)
    .lineTo(document.page.width - document.page.margins.right, document.y + 4)
    .lineWidth(1)
    .strokeColor('#cbd5e1')
    .stroke();
  document.moveDown(0.8);
};

const writeField = (document, label, value) => {
  document
    .font('Helvetica-Bold')
    .fontSize(10)
    .fillColor('#334155')
    .text(label, { continued: true });
  document
    .font('Helvetica')
    .fillColor('#0f172a')
    .text(` ${value ?? 'n/a'}`);
};

const writeParagraph = (document, value) => {
  document
    .font('Helvetica')
    .fontSize(10)
    .fillColor('#0f172a')
    .text(value || 'n/a', {
      align: 'left',
    });
};

const writeBulletList = (document, items) => {
  if (!items.length) {
    writeParagraph(document, 'None');
    return;
  }

  items.forEach(item => {
    document
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#0f172a')
      .text(`- ${item}`);
  });
};

const buildRecommendations = analysis => {
  switch (analysis.verdict) {
    case 'malicious':
      return [
        'Isolate the affected host or account if the binary executed recently.',
        'Preserve the binary, PCAP window and related logs for incident response.',
        'Review lateral movement and persistence indicators around the same timestamp.',
      ];
    case 'suspicious':
      return [
        'Validate the binary origin, signer and expected deployment path.',
        'Correlate with the traffic event, user session and host telemetry before allowlisting.',
        'Consider a second sandbox run or static reverse engineering for confirmation.',
      ];
    case 'clean':
      return [
        'Correlate the clean sandbox result with the triggering network behavior before allowlisting.',
        'Keep the hash for future baselining if the file belongs to a trusted application.',
      ];
    default:
      return [
        'Review CAPE availability, task status and timeout settings.',
        'Retry the submission after confirming the file still exists and the sandbox workers are healthy.',
      ];
  }
};

const extractBehaviorSummary = raw => {
  const behaviorSummary = raw?.behavior?.summary;
  if (!behaviorSummary || typeof behaviorSummary !== 'object') {
    return [];
  }

  const lines = [];
  for (const [key, value] of Object.entries(behaviorSummary)) {
    if (Array.isArray(value) && value.length > 0) {
      lines.push(`${key}: ${value.slice(0, 3).join(', ')}${value.length > 3 ? '...' : ''}`);
    }
  }
  return lines.slice(0, 8);
};

const extractStaticSummary = raw => {
  const staticAnalysis = raw?.staticAnalysis;
  if (!staticAnalysis || typeof staticAnalysis !== 'object') {
    return [];
  }

  const lines = [];
  if (staticAnalysis.fileType) {
    lines.push(`Type: ${staticAnalysis.fileType}`);
  }
  if (Number.isFinite(staticAnalysis.entropy)) {
    lines.push(`File entropy: ${Number(staticAnalysis.entropy).toFixed(3)}`);
  }
  if (staticAnalysis.pe?.machine || staticAnalysis.pe?.subsystem) {
    lines.push(`PE platform: ${staticAnalysis.pe?.machine || 'n/a'} / ${staticAnalysis.pe?.subsystem || 'n/a'}`);
  }
  if (staticAnalysis.pe?.compileTimestamp) {
    lines.push(`Compile timestamp: ${formatTimestamp(staticAnalysis.pe.compileTimestamp)}`);
  }
  if (Array.isArray(staticAnalysis.pe?.sections) && staticAnalysis.pe.sections.length > 0) {
    const highEntropySections = staticAnalysis.pe.sections
      .filter(section => Number(section?.entropy) >= 7.2)
      .map(section => `${section.name} (${Number(section.entropy).toFixed(2)})`);
    if (highEntropySections.length > 0) {
      lines.push(`High-entropy sections: ${highEntropySections.join(', ')}`);
    }
  }
  if (staticAnalysis.importSignals) {
    const importHighlights = Object.entries(staticAnalysis.importSignals)
      .filter(([, values]) => Array.isArray(values) && values.length > 0)
      .map(([category, values]) => `${category}: ${values.slice(0, 3).join(', ')}${values.length > 3 ? '...' : ''}`);
    lines.push(...importHighlights.slice(0, 6));
  }
  if (staticAnalysis.strings?.indicators) {
    const indicators = staticAnalysis.strings.indicators;
    if (Array.isArray(indicators.urls) && indicators.urls.length > 0) {
      lines.push(`URLs: ${indicators.urls.slice(0, 3).join(', ')}${indicators.urls.length > 3 ? '...' : ''}`);
    }
    if (Array.isArray(indicators.commands) && indicators.commands.length > 0) {
      lines.push(`Commands: ${indicators.commands.slice(0, 2).join(', ')}${indicators.commands.length > 2 ? '...' : ''}`);
    }
    if (Array.isArray(indicators.registryKeys) && indicators.registryKeys.length > 0) {
      lines.push(`Registry keys: ${indicators.registryKeys.slice(0, 2).join(', ')}${indicators.registryKeys.length > 2 ? '...' : ''}`);
    }
  }

  return lines.slice(0, 12);
};

const extractDecompilerSummary = raw => {
  const decompilation = raw?.decompilation;
  if (!decompilation || typeof decompilation !== 'object') {
    return [];
  }

  const lines = [];
  if (decompilation.engine) {
    lines.push(`Engine: ${decompilation.engine}`);
  }
  if (decompilation.mode) {
    lines.push(`Mode: ${decompilation.mode}`);
  }
  if (decompilation.entryPointRva) {
    lines.push(`Entry point: ${decompilation.entryPointRva}`);
  }
  if (decompilation.entryPointBytes) {
    lines.push(`Entry bytes: ${decompilation.entryPointBytes}`);
  }
  if (Array.isArray(decompilation.pseudoCode)) {
    lines.push(...decompilation.pseudoCode.slice(0, 10));
  }

  return lines.slice(0, 14);
};

const extractLlmReview = raw => {
  const review = raw?.llmReview;
  if (!review || typeof review !== 'object') {
    return [];
  }

  const lines = [];
  if (review.executiveSummary) {
    lines.push(review.executiveSummary);
  }
  if (Array.isArray(review.suspectedCapabilities) && review.suspectedCapabilities.length > 0) {
    lines.push(`Capabilities: ${review.suspectedCapabilities.join(', ')}`);
  }
  if (Array.isArray(review.recommendedNextSteps) && review.recommendedNextSteps.length > 0) {
    lines.push(...review.recommendedNextSteps.map(step => `Next step: ${step}`));
  }
  if (review.reason) {
    lines.push(`LLM review skipped: ${review.reason}`);
  }

  return lines.slice(0, 10);
};

const extractDynamicExecutionSummary = raw => {
  const execution = raw?.execution;
  if (!execution || typeof execution !== 'object') {
    return [];
  }

  const lines = [];
  lines.push(`Mode: ${execution.mode || execution.platform || 'n/a'}`);
  lines.push(`Status: ${execution.status || 'n/a'}`);
  if (execution.reason) {
    lines.push(`Reason: ${execution.reason}`);
  }
  if (execution.runtimeSeconds) {
    lines.push(`Runtime: ${execution.runtimeSeconds} seconds`);
  }
  if (execution.startedAt) {
    lines.push(`Started: ${formatTimestamp(execution.startedAt)}`);
  }
  if (execution.finishedAt) {
    lines.push(`Finished: ${formatTimestamp(execution.finishedAt)}`);
  }
  if (execution.execution?.commandLine) {
    lines.push(`Launch command: ${execution.execution.commandLine}`);
  }
  if (Array.isArray(execution.processes) && execution.processes.length > 0) {
    lines.push(`Processes: ${execution.processes.slice(0, 5).map(processEntry => processEntry.name || processEntry.commandLine || processEntry.processId).join(', ')}`);
  }
  if (Array.isArray(execution.network?.tcp) && execution.network.tcp.length > 0) {
    lines.push(`TCP: ${execution.network.tcp.slice(0, 4).map(connection => `${connection.remoteAddress}:${connection.remotePort}`).join(', ')}`);
  }
  if (Array.isArray(execution.network?.udp) && execution.network.udp.length > 0) {
    lines.push(`UDP endpoints: ${execution.network.udp.slice(0, 4).map(connection => `${connection.localAddress}:${connection.localPort}`).join(', ')}`);
  }
  if (Array.isArray(execution.files?.added) && execution.files.added.length > 0) {
    lines.push(`Added files: ${execution.files.added.slice(0, 4).map(file => file.path).join(', ')}`);
  }
  if (Array.isArray(execution.registry?.runKeys) && execution.registry.runKeys.length > 0) {
    lines.push(`Autoruns: ${execution.registry.runKeys.slice(0, 4).map(entry => `${entry.name}=${entry.value}`).join(', ')}`);
  }
  if (Array.isArray(execution.services?.created) && execution.services.created.length > 0) {
    lines.push(`Created services: ${execution.services.created.slice(0, 4).map(service => service.name).join(', ')}`);
  }

  return lines.slice(0, 14);
};

const extractPromptInjectionSummary = raw => {
  const indicators = raw?.staticAnalysis?.strings?.indicators;
  if (!indicators || typeof indicators !== 'object') {
    return [];
  }

  const lines = [];
  if (Array.isArray(indicators.promptInjectionSignals) && indicators.promptInjectionSignals.length > 0) {
    lines.push(`Detected signals: ${indicators.promptInjectionSignals.join(', ')}`);
  }
  if (Array.isArray(indicators.promptInjectionExcerpts) && indicators.promptInjectionExcerpts.length > 0) {
    lines.push(...indicators.promptInjectionExcerpts.slice(0, 8).map(excerpt => `Excerpt: ${excerpt}`));
  }

  return lines.slice(0, 12);
};

export const buildSandboxReportFileName = analysis =>
  sanitizeFileName(`sandbox-report_${analysis.createdAt.slice(0, 19).replace(/[:T]/g, '-')}_${analysis.fileName.replace(/\.[^.]+$/, '')}_${analysis.verdict}.pdf`);

export const renderSandboxPdfReport = analysis => new Promise((resolve, reject) => {
  const document = new PDFDocument({
    size: 'A4',
    margin: 50,
    info: {
      Title: `NetGuard AI Sandbox Report - ${analysis.fileName}`,
      Author: 'NetGuard AI',
      Subject: 'Sandbox analysis report',
      Keywords: 'NetGuard AI, sandbox, CAPE, malware analysis, SOC',
      CreationDate: new Date(),
    },
  });

  const chunks = [];
  document.on('data', chunk => chunks.push(chunk));
  document.on('end', () => resolve(Buffer.concat(chunks)));
  document.on('error', reject);

  const raw = analysis.raw ?? null;
  const targetFile = raw?.target?.file ?? {};
  const info = raw?.info ?? {};

  document
    .font('Helvetica-Bold')
    .fontSize(22)
    .fillColor('#0f172a')
    .text('NetGuard AI Sandbox Report');

  document
    .moveDown(0.4)
    .font('Helvetica')
    .fontSize(11)
    .fillColor('#475569')
    .text(`Generated ${formatTimestamp(new Date().toISOString())}`)
    .text(`Analysis ID ${analysis.id}`);

  startSection(document, 'Executive Summary');
  writeField(document, 'Verdict:', formatVerdict(analysis.verdict));
  writeField(document, 'Status:', formatStatus(analysis.status));
  writeField(document, 'Score:', formatScore(analysis.score));
  writeField(document, 'Provider:', String(analysis.provider).toUpperCase());
  writeField(document, 'Sensor:', `${analysis.sensorName} (${analysis.sensorId})`);
  writeParagraph(document, analysis.summary);

  startSection(document, 'File Details');
  writeField(document, 'File name:', analysis.fileName);
  writeField(document, 'File path:', analysis.filePath);
  writeField(document, 'File size:', formatBytes(analysis.fileSize));
  writeField(document, 'SHA-256:', analysis.sha256);
  writeField(document, 'SHA-1:', targetFile.sha1 || 'n/a');
  writeField(document, 'MD5:', targetFile.md5 || 'n/a');
  writeField(document, 'Type:', targetFile.type || info.package || 'n/a');
  writeField(document, 'Process name:', analysis.processName || 'n/a');

  startSection(document, 'Sandbox Execution');
  writeField(document, 'Created at:', formatTimestamp(analysis.createdAt));
  writeField(document, 'Updated at:', formatTimestamp(analysis.updatedAt));
  writeField(document, 'External task ID:', analysis.externalTaskId || 'n/a');
  writeField(document, 'Report URL:', analysis.reportUrl || 'n/a');
  writeField(document, 'Traffic event ID:', analysis.trafficEventId || 'n/a');
  writeField(document, 'Machine / package:', `${info.machine?.name || 'n/a'} / ${info.package || 'n/a'}`);
  if (analysis.errorMessage) {
    writeField(document, 'Error:', analysis.errorMessage);
  }

  startSection(document, 'Signatures');
  writeBulletList(document, analysis.signatures);

  startSection(document, 'Behavior Highlights');
  writeBulletList(document, extractBehaviorSummary(raw));

  const staticSummary = extractStaticSummary(raw);
  if (staticSummary.length > 0) {
    startSection(document, 'Static Reverse Analysis');
    writeBulletList(document, staticSummary);
  }

  const decompilerSummary = extractDecompilerSummary(raw);
  if (decompilerSummary.length > 0) {
    startSection(document, 'Decompiler Output');
    writeBulletList(document, decompilerSummary);
  }

  const llmReview = extractLlmReview(raw);
  if (llmReview.length > 0) {
    startSection(document, 'Analyst Review');
    writeBulletList(document, llmReview);
  }

  const dynamicExecutionSummary = extractDynamicExecutionSummary(raw);
  if (dynamicExecutionSummary.length > 0) {
    startSection(document, 'Dynamic Execution');
    writeBulletList(document, dynamicExecutionSummary);
  }

  const promptInjectionSummary = extractPromptInjectionSummary(raw);
  if (promptInjectionSummary.length > 0) {
    startSection(document, 'Prompt Injection Indicators');
    writeBulletList(document, promptInjectionSummary);
  }

  startSection(document, 'Recommended SOC Actions');
  writeBulletList(document, buildRecommendations(analysis));

  document
    .moveDown(1.5)
    .font('Helvetica')
    .fontSize(9)
    .fillColor('#64748b')
    .text(
      'This report was generated automatically by NetGuard AI from the persisted sandbox analysis record. Validate verdicts with host and network telemetry before taking irreversible containment actions.',
      {
        align: 'left',
      }
    );

  document.end();
});
