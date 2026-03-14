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
const BENIGN_AUTORUN_PATTERN = /(microsoftedgeautolaunch|msedge\.exe.*--no-startup-window.*--win-session-start)/i;
const isMeaningfulRemoteTcp = connection => {
  const remoteAddress = String(connection?.remoteAddress || '').trim().toLowerCase();
  const remotePort = Number(connection?.remotePort) || 0;
  const state = String(connection?.state || '').trim().toLowerCase();

  if (!remoteAddress || remotePort <= 0 || state === 'listen') {
    return false;
  }

  if (remoteAddress === '0.0.0.0' || remoteAddress === '::' || remoteAddress === '::1' || remoteAddress === '127.0.0.1') {
    return false;
  }

  return !remoteAddress.startsWith('127.') && !remoteAddress.startsWith('::ffff:127.');
};

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

const formatProcessEvidence = processEntry => {
  if (!processEntry || typeof processEntry !== 'object') {
    return 'n/a';
  }

  const parts = [];
  parts.push(processEntry.name || processEntry.commandLine || processEntry.processId || 'unknown');
  if (processEntry.parentName) {
    parts.push(`parent=${processEntry.parentName}`);
  }
  if (processEntry.creationTimeUtc) {
    parts.push(`started=${formatTimestamp(processEntry.creationTimeUtc)}`);
  }
  if (processEntry.commandLine) {
    parts.push(`cmd=${processEntry.commandLine}`);
  }
  return parts.join(' | ');
};

const formatClassifiedConnection = connection => {
  if (!connection || typeof connection !== 'object') {
    return 'n/a';
  }

  const parts = [`${connection.remoteAddress || connection.remote_address}:${connection.remotePort || connection.remote_port}`];
  const provider = connection.providerCategory || connection.provider_category;
  const relation = connection.documentRelation || connection.document_relation;
  const matchedHosts = connection.matchedDocumentHosts || connection.matched_document_hosts || [];
  if (provider) {
    parts.push(`provider=${provider}`);
  }
  if (relation) {
    parts.push(`relation=${relation}`);
  }
  if (Array.isArray(matchedHosts) && matchedHosts.length > 0) {
    parts.push(`matched=${matchedHosts.join(', ')}`);
  }
  return parts.join(' | ');
};

const buildRecommendations = analysis => {
  const dynamicFindings = analysis?.raw?.dynamicAssessment?.findings;
  if (
    dynamicFindings?.secondaryCodeExecutionConfirmed
    || dynamicFindings?.payloadDropConfirmed
    || dynamicFindings?.payloadExecutionConfirmed
    || dynamicFindings?.secondaryNetworkCommunicationConfirmed
  ) {
    return [
      'Isolate the affected host or account until the dropped files, child processes and outbound destinations are triaged.',
      'Preserve the dropped payloads, Windows Sandbox artifacts, PCAP window and related logs for incident response.',
      'Review the confirmed child processes, autoruns and remote endpoints for follow-on execution or lateral movement.',
    ];
  }

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

  return lines.slice(0, 24);
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

  const findings = raw?.dynamicAssessment?.findings && typeof raw.dynamicAssessment.findings === 'object'
    ? raw.dynamicAssessment.findings
    : null;
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
  if (findings) {
    lines.push(`Viewer launch observed: ${findings.viewerLaunchObserved ? `yes (${findings.viewerProcessName || execution.execution?.processName || 'unknown process'})` : 'no'}`);
    lines.push(`Secondary executable code: ${findings.secondaryCodeExecutionConfirmed ? 'confirmed' : 'not confirmed'}`);
    if (findings.secondaryCodeExecutionConfirmed) {
      const secondaryProcesses = Array.isArray(findings.secondaryExecutionProcesses) ? findings.secondaryExecutionProcesses : [];
      const suspiciousProcesses = Array.isArray(findings.suspiciousExecutionProcesses) ? findings.suspiciousExecutionProcesses : [];
      const evidenceProcesses = [...secondaryProcesses, ...suspiciousProcesses]
        .map(formatProcessEvidence)
        .filter(Boolean);
      if (evidenceProcesses.length > 0) {
        lines.push(`Secondary processes: ${evidenceProcesses.slice(0, 6).join(', ')}`);
      }
    } else if (Array.isArray(findings.unattributedProcesses) && findings.unattributedProcesses.length > 0) {
      lines.push(`Unattributed new processes: ${findings.unattributedProcesses.slice(0, 6).map(formatProcessEvidence).join(', ')}`);
    }
    lines.push(`Dropped payloads: ${findings.payloadDropConfirmed ? 'confirmed' : 'not confirmed'}`);
    if (findings.payloadDropConfirmed && Array.isArray(findings.droppedPayloads) && findings.droppedPayloads.length > 0) {
      lines.push(`Dropped payload evidence: ${findings.droppedPayloads.slice(0, 6).map(file => `${file.path} [${file.signatureType || file.extension || 'unknown'}]`).join(', ')}`);
    }
    if (findings.payloadExecutionConfirmed && Array.isArray(findings.executedDroppedPayloads) && findings.executedDroppedPayloads.length > 0) {
      lines.push(`Executed dropped payloads: ${findings.executedDroppedPayloads.slice(0, 4).map(file => file.path).join(', ')}`);
    }
    const networkVerdict = findings.secondaryNetworkCommunicationConfirmed
      ? 'confirmed from secondary processes'
      : findings.viewerNetworkCommunicationObserved
        ? 'observed from viewer context only'
        : findings.networkCommunicationConfirmed
          ? 'confirmed'
          : 'not confirmed';
    lines.push(`Remote network communication: ${networkVerdict}`);
    if (findings.secondaryNetworkCommunicationConfirmed && Array.isArray(findings.secondaryRemoteTcpConnections) && findings.secondaryRemoteTcpConnections.length > 0) {
      lines.push(`Secondary remote TCP evidence: ${findings.secondaryRemoteTcpConnections.slice(0, 6).map(formatClassifiedConnection).join(', ')}`);
    } else if (findings.viewerNetworkCommunicationObserved && Array.isArray(findings.remoteTcpConnections) && findings.remoteTcpConnections.length > 0) {
      lines.push(`Viewer remote TCP evidence: ${findings.remoteTcpConnections.slice(0, 6).map(formatClassifiedConnection).join(', ')}`);
    }
  }
  if (Array.isArray(execution.processes) && execution.processes.length > 0) {
    lines.push(`Processes: ${execution.processes.slice(0, 5).map(processEntry => processEntry.name || processEntry.commandLine || processEntry.processId).join(', ')}`);
  }
  const meaningfulTcpConnections = Array.isArray(execution.network?.tcp)
    ? execution.network.tcp.filter(isMeaningfulRemoteTcp)
    : [];
  if (meaningfulTcpConnections.length > 0) {
    lines.push(`TCP: ${meaningfulTcpConnections.slice(0, 4).map(connection => `${connection.remoteAddress}:${connection.remotePort}`).join(', ')}`);
  }
  if (Array.isArray(execution.network?.udp) && execution.network.udp.length > 0) {
    lines.push(`UDP endpoints: ${execution.network.udp.slice(0, 4).map(connection => `${connection.localAddress}:${connection.localPort}`).join(', ')}`);
  }
  if (Array.isArray(execution.files?.added) && execution.files.added.length > 0) {
    lines.push(`Added files: ${execution.files.added.slice(0, 4).map(file => file.path).join(', ')}`);
  }
  const suspiciousRunKeys = Array.isArray(execution.registry?.runKeys)
    ? execution.registry.runKeys.filter(entry => !BENIGN_AUTORUN_PATTERN.test(`${entry?.name || ''} ${entry?.value || ''}`))
    : [];
  if (suspiciousRunKeys.length > 0) {
    lines.push(`Autoruns: ${suspiciousRunKeys.slice(0, 4).map(entry => `${entry.name}=${entry.value}`).join(', ')}`);
  }
  if (Array.isArray(execution.services?.created) && execution.services.created.length > 0) {
    lines.push(`Created services: ${execution.services.created.slice(0, 4).map(service => service.name).join(', ')}`);
  }

  return lines.slice(0, 18);
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

const extractOfficeStructuralSummary = raw => {
  const office = raw?.staticAnalysis?.office;
  if (!office || typeof office !== 'object') {
    return [];
  }

  const lines = [];
  if (office.description || office.format) {
    lines.push(`Type: ${office.description || office.format}`);
  }
  if (office.subtype) {
    lines.push(`Subtype: ${office.subtype}`);
  }
  if (Number.isFinite(office.entryCount)) {
    lines.push(`Package entries: ${office.entryCount}`);
  }
  if (office.macroProject?.present) {
    lines.push(`Macro project: ${(office.macroProject.entries || []).join(', ') || 'present'}`);
  }
  if ((office.macroProject?.autoExecIndicators || []).length > 0) {
    lines.push(`Autoexec indicators: ${office.macroProject.autoExecIndicators.slice(0, 6).join(', ')}`);
  }
  if ((office.macroProject?.executionIndicators || []).length > 0) {
    lines.push(`Macro execution indicators: ${office.macroProject.executionIndicators.slice(0, 6).join(', ')}`);
  }
  if (office.embeddedObjects?.present) {
    lines.push(`Embedded objects: ${office.embeddedObjects.entries?.slice(0, 6).join(', ') || office.embeddedObjects.count}`);
  }
  if (office.activeX?.present) {
    lines.push(`ActiveX entries: ${office.activeX.entries?.slice(0, 6).join(', ') || 'present'}`);
  }
  if (office.externalRelationships?.present) {
    lines.push(`External relationships: ${office.externalRelationships.targets?.slice(0, 6).join(', ') || office.externalRelationships.count}`);
  }
  if (office.dde?.present) {
    lines.push(`DDE fields: ${office.dde.indicators?.slice(0, 6).join(', ')}`);
  }
  if ((office.customUiEntries || []).length > 0) {
    lines.push(`Custom UI entries: ${office.customUiEntries.slice(0, 6).join(', ')}`);
  }
  if ((office.urls || []).length > 0) {
    lines.push(`Document URLs: ${office.urls.slice(0, 6).join(', ')}`);
  }

  return lines.slice(0, 14);
};

const extractPdfStructuralSummary = raw => {
  const pdf = raw?.staticAnalysis?.pdf;
  if (!pdf || typeof pdf !== 'object') {
    return [];
  }

  const lines = [];
  if (pdf.version) {
    lines.push(`Version: PDF ${pdf.version}`);
  }
  if (Number.isFinite(pdf.objectCount)) {
    lines.push(`Objects: ${pdf.objectCount}`);
  }
  if (Number.isFinite(pdf.pageCount)) {
    lines.push(`Pages: ${pdf.pageCount}`);
  }
  if (Number.isFinite(pdf.streamCount)) {
    lines.push(`Streams: ${pdf.streamCount}`);
  }
  if ((pdf.objectStreamCount || 0) > 0) {
    lines.push(`Object streams: ${pdf.objectStreamCount}`);
  }
  if ((pdf.xrefStreamCount || 0) > 0) {
    lines.push(`XRef streams: ${pdf.xrefStreamCount}`);
  }
  if (pdf.javascript?.present) {
    lines.push(`JavaScript indicators: ${pdf.javascript.indicators?.join(', ') || 'present'}`);
  }
  if (pdf.autoActions?.present) {
    lines.push(`Automatic actions: ${pdf.autoActions.indicators?.join(', ') || 'present'}`);
  }
  if (pdf.launchActions?.present) {
    lines.push(`Launch actions: ${pdf.launchActions.indicators?.join(', ') || 'present'}`);
  }
  if (pdf.embeddedFiles?.present) {
    lines.push(`Embedded files: ${pdf.embeddedFiles.names?.join(', ') || pdf.embeddedFiles.count}`);
  }
  if (pdf.uriActions?.present) {
    lines.push(`External URIs: ${pdf.uriActions.urls?.join(', ') || pdf.uriActions.count}`);
  }
  if ((pdf.streamEntropy?.highEntropyStreamCount || 0) > 0) {
    lines.push(`High-entropy streams: ${pdf.streamEntropy.suspiciousStreams?.join(', ') || pdf.streamEntropy.highEntropyStreamCount}`);
  }
  if (pdf.embeddedPayloads?.present) {
    if (pdf.validatedPortableExecutables?.present) {
      lines.push(`Validated embedded PE: ${pdf.validatedPortableExecutables.hits?.map(hit => `${hit.type}@${hit.offset}${hit.validation?.machine ? ` (${hit.validation.machine}${hit.validation?.subsystem ? ` / ${hit.validation.subsystem}` : ''})` : ''}`).join(', ') || pdf.validatedPortableExecutables.count}`);
    }
    const executableHits = (pdf.embeddedPayloads.hits || []).filter(hit => hit?.type === 'portable-executable');
    if (executableHits.length > 0) {
      lines.push(`Embedded executable code: ${executableHits.slice(0, 8).map(hit => `${hit.type}@${hit.offset}`).join(', ')}`);
    }
    lines.push(`Embedded payload signatures: ${pdf.embeddedPayloads.hits?.map(hit => `${hit.type}@${hit.offset}`).join(', ') || pdf.embeddedPayloads.count}`);
  }

  return lines.slice(0, 14);
};

const extractImageStructuralSummary = raw => {
  const image = raw?.staticAnalysis?.image;
  if (!image || typeof image !== 'object') {
    return [];
  }

  const lines = [];
  if (image.description || image.format) {
    lines.push(`Format: ${image.description || image.format}`);
  }
  if (Number.isFinite(image.width) && Number.isFinite(image.height)) {
    lines.push(`Dimensions: ${image.width} x ${image.height}`);
  }
  if (typeof image.animated === 'boolean') {
    lines.push(`Animated: ${image.animated ? 'yes' : 'no'}`);
  }
  if ((image.metadata?.textEntryCount || 0) > 0) {
    lines.push(`Metadata text entries: ${image.metadata.textEntryCount}`);
  }
  if ((image.metadata?.customChunks || []).length > 0) {
    lines.push(`Custom chunks/segments: ${image.metadata.customChunks.slice(0, 6).join(', ')}`);
  }
  if ((image.metadata?.suspiciousIndicators || []).length > 0) {
    lines.push(`Suspicious metadata: ${image.metadata.suspiciousIndicators.join(', ')}`);
  }
  if (image.activeContent?.present) {
    lines.push(`Active content: ${(image.activeContent.indicators || []).slice(0, 6).join(', ') || 'present'}`);
  }
  if ((image.activeContent?.externalReferences || []).length > 0) {
    lines.push(`External references: ${image.activeContent.externalReferences.slice(0, 6).join(', ')}`);
  }
  if (image.appendedPayload?.present) {
    lines.push(`Appended payload: ${image.appendedPayload.bytes} bytes`);
  }
  if ((image.appendedPayload?.hits || []).length > 0) {
    lines.push(`Embedded payload signatures: ${image.appendedPayload.hits.slice(0, 6).map(hit => `${hit.type}@${hit.offset}`).join(', ')}`);
  }

  return lines.slice(0, 14);
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

  const officeStructuralSummary = extractOfficeStructuralSummary(raw);
  if (officeStructuralSummary.length > 0) {
    startSection(document, 'Office Structural Analysis');
    writeBulletList(document, officeStructuralSummary);
  }

  const pdfStructuralSummary = extractPdfStructuralSummary(raw);
  if (pdfStructuralSummary.length > 0) {
    startSection(document, 'PDF Structural Analysis');
    writeBulletList(document, pdfStructuralSummary);
  }

  const imageStructuralSummary = extractImageStructuralSummary(raw);
  if (imageStructuralSummary.length > 0) {
    startSection(document, 'Image Structural Analysis');
    writeBulletList(document, imageStructuralSummary);
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
