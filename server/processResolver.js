import os from 'node:os';
import { spawn } from 'node:child_process';

const DEFAULT_REFRESH_INTERVAL_MS = 2_500;
const BINARY_METADATA_TTL_MS = 10 * 60 * 1000;
const PROCESS_QUERY_TIMEOUT_MS = 8_000;
const ERROR_THROTTLE_MS = 60_000;

const WINDOWS_PROCESS_QUERY = `
$tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess)
$processIds = @($tcp.OwningProcess + $udp.OwningProcess | Where-Object { $_ -ne $null } | Sort-Object -Unique)
$processFilter = ($processIds | ForEach-Object { "ProcessId = $_" }) -join ' OR '
$processes = if ($processFilter) {
  @(Get-CimInstance Win32_Process -Filter $processFilter -ErrorAction SilentlyContinue | Select-Object ProcessId,Name,ExecutablePath,CommandLine)
} else {
  @()
}
$services = if ($processIds.Count -gt 0) {
  @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -in $processIds } | Select-Object Name,DisplayName,State,ProcessId)
} else {
  @()
}
[pscustomobject]@{
  tcp = $tcp
  udp = $udp
  processes = $processes
  services = $services
} | ConvertTo-Json -Depth 6 -Compress
`.trim();

const buildBinaryMetadataQuery = (executablePath) => `
$targetPath = '${executablePath.replace(/'/g, "''")}'
$item = Get-Item -LiteralPath $targetPath -ErrorAction Stop
$signature = Get-AuthenticodeSignature -LiteralPath $targetPath -ErrorAction SilentlyContinue
[pscustomobject]@{
  companyName = $item.VersionInfo.CompanyName
  fileDescription = $item.VersionInfo.FileDescription
  signatureStatus = if ($signature) { [string]$signature.Status } else { $null }
  signerSubject = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
} | ConvertTo-Json -Depth 4 -Compress
`.trim();

const normalizeAddress = (address) => {
  if (!address) {
    return '*';
  }

  const normalizedAddress = String(address).trim().toLowerCase();
  if (!normalizedAddress || normalizedAddress === '0.0.0.0' || normalizedAddress === '::' || normalizedAddress === '[::]') {
    return '*';
  }

  return normalizedAddress.startsWith('::ffff:')
    ? normalizedAddress.slice(7)
    : normalizedAddress;
};

const normalizeNumber = (value) => {
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
};

const normalizeText = (value) => {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmedValue = value.trim();
  return trimmedValue ? trimmedValue : null;
};

const buildExactKey = ({ protocol, localAddress, localPort, remoteAddress, remotePort }) =>
  `${protocol}|${normalizeAddress(localAddress)}|${localPort}|${normalizeAddress(remoteAddress)}|${remotePort}`;

const buildListenerKey = ({ protocol, localAddress, localPort }) =>
  `${protocol}|${normalizeAddress(localAddress)}|${localPort}`;

const buildLocalPortKey = ({ protocol, localPort }) => `${protocol}|${localPort}`;

const createEmptySnapshot = () => ({
  exactEndpoints: new Map(),
  listenerEndpoints: new Map(),
  localPortEndpoints: new Map(),
});

const executeProcessQuery = (command, script) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      child.kill();
      reject(new Error('Local process query timed out.'));
    }, PROCESS_QUERY_TIMEOUT_MS);

    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
    });

    child.on('error', error => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });

    child.on('close', code => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (code === 0) {
        resolve(stdout.trim());
        return;
      }

      reject(new Error(stderr.trim() || stdout.trim() || `Local process query exited with code ${code}.`));
    });
  });

const parseProcessQueryResponse = (payload) => {
  if (!payload) {
    return { tcp: [], udp: [], processes: [], services: [] };
  }

  const parsed = JSON.parse(payload);
  return {
    tcp: Array.isArray(parsed.tcp) ? parsed.tcp : parsed.tcp ? [parsed.tcp] : [],
    udp: Array.isArray(parsed.udp) ? parsed.udp : parsed.udp ? [parsed.udp] : [],
    processes: Array.isArray(parsed.processes) ? parsed.processes : parsed.processes ? [parsed.processes] : [],
    services: Array.isArray(parsed.services) ? parsed.services : parsed.services ? [parsed.services] : [],
  };
};

const buildProcessEntry = (endpoint, process, services, resolution) => ({
  pid: normalizeNumber(endpoint.OwningProcess ?? endpoint.owningProcess ?? process?.ProcessId ?? process?.pid),
  name: normalizeText(process?.Name ?? process?.name),
  executablePath: normalizeText(process?.ExecutablePath ?? process?.executablePath),
  commandLine: normalizeText(process?.CommandLine ?? process?.commandLine),
  companyName: null,
  fileDescription: null,
  signatureStatus: null,
  signerSubject: null,
  services,
  localAddress: endpoint.LocalAddress ?? endpoint.localAddress ?? null,
  localPort: normalizeNumber(endpoint.LocalPort ?? endpoint.localPort) ?? 0,
  remoteAddress: endpoint.RemoteAddress ?? endpoint.remoteAddress ?? null,
  remotePort: normalizeNumber(endpoint.RemotePort ?? endpoint.remotePort),
  protocol: endpoint.protocol,
  resolution,
});

const addIfMissing = (map, key, value) => {
  if (!map.has(key)) {
    map.set(key, value);
  }
};

const buildSnapshot = ({ tcp, udp, processes, services }) => {
  const snapshot = createEmptySnapshot();
  const processMap = new Map(
    processes.map(process => [normalizeNumber(process.ProcessId ?? process.pid), process])
      .filter(([processId]) => processId !== null)
  );
  const servicesByPid = new Map();

  for (const service of services) {
    const processId = normalizeNumber(service.ProcessId ?? service.processId);
    if (processId === null) {
      continue;
    }

    const existingServices = servicesByPid.get(processId) ?? [];
    existingServices.push({
      name: normalizeText(service.Name ?? service.name) ?? 'UnknownService',
      displayName: normalizeText(service.DisplayName ?? service.displayName),
      state: normalizeText(service.State ?? service.state),
    });
    servicesByPid.set(processId, existingServices);
  }

  for (const tcpEndpoint of tcp) {
    const localPort = normalizeNumber(tcpEndpoint.LocalPort ?? tcpEndpoint.localPort);
    const remotePort = normalizeNumber(tcpEndpoint.RemotePort ?? tcpEndpoint.remotePort);
    if (!localPort || remotePort === null) {
      continue;
    }

    const endpoint = {
      ...tcpEndpoint,
      protocol: 'TCP',
    };
    const processId = normalizeNumber(tcpEndpoint.OwningProcess ?? tcpEndpoint.owningProcess);
    const process = processMap.get(processId);
    const processServices = servicesByPid.get(processId) ?? [];

    addIfMissing(snapshot.exactEndpoints, buildExactKey({
      protocol: 'TCP',
      localAddress: tcpEndpoint.LocalAddress ?? tcpEndpoint.localAddress,
      localPort,
      remoteAddress: tcpEndpoint.RemoteAddress ?? tcpEndpoint.remoteAddress,
      remotePort,
    }), buildProcessEntry(endpoint, process, processServices, 'exact'));

    if (String(tcpEndpoint.State ?? tcpEndpoint.state).toLowerCase() === 'listen') {
      addIfMissing(snapshot.listenerEndpoints, buildListenerKey({
        protocol: 'TCP',
        localAddress: tcpEndpoint.LocalAddress ?? tcpEndpoint.localAddress,
        localPort,
      }), buildProcessEntry(endpoint, process, processServices, 'listener'));
    }

    addIfMissing(snapshot.localPortEndpoints, buildLocalPortKey({
      protocol: 'TCP',
      localPort,
    }), buildProcessEntry(endpoint, process, processServices, 'local_port'));
  }

  for (const udpEndpoint of udp) {
    const localPort = normalizeNumber(udpEndpoint.LocalPort ?? udpEndpoint.localPort);
    if (!localPort) {
      continue;
    }

    const endpoint = {
      ...udpEndpoint,
      protocol: 'UDP',
      RemoteAddress: null,
      RemotePort: null,
    };
    const processId = normalizeNumber(udpEndpoint.OwningProcess ?? udpEndpoint.owningProcess);
    const process = processMap.get(processId);
    const processServices = servicesByPid.get(processId) ?? [];

    addIfMissing(snapshot.listenerEndpoints, buildListenerKey({
      protocol: 'UDP',
      localAddress: udpEndpoint.LocalAddress ?? udpEndpoint.localAddress,
      localPort,
    }), buildProcessEntry(endpoint, process, processServices, 'listener'));

    addIfMissing(snapshot.localPortEndpoints, buildLocalPortKey({
      protocol: 'UDP',
      localPort,
    }), buildProcessEntry(endpoint, process, processServices, 'local_port'));
  }

  return snapshot;
};

const deriveLocalEndpointCandidates = (packet) => {
  const protocol = packet.protocol;
  if (protocol !== 'TCP' && protocol !== 'UDP') {
    return [];
  }

  if (packet.direction === 'OUTBOUND') {
    return [{
      protocol,
      localAddress: packet.sourceIp,
      localPort: packet.sourcePort,
      remoteAddress: packet.destinationIp,
      remotePort: packet.destinationPort,
    }];
  }

  if (packet.direction === 'INBOUND') {
    return [{
      protocol,
      localAddress: packet.destinationIp,
      localPort: packet.destinationPort,
      remoteAddress: packet.sourceIp,
      remotePort: packet.sourcePort,
    }];
  }

  return [
    {
      protocol,
      localAddress: packet.sourceIp,
      localPort: packet.sourcePort,
      remoteAddress: packet.destinationIp,
      remotePort: packet.destinationPort,
    },
    {
      protocol,
      localAddress: packet.destinationIp,
      localPort: packet.destinationPort,
      remoteAddress: packet.sourceIp,
      remotePort: packet.sourcePort,
    },
  ];
};

export class ProcessResolver {
  constructor({ refreshIntervalMs = DEFAULT_REFRESH_INTERVAL_MS, onError } = {}) {
    this.platform = os.platform();
    this.refreshIntervalMs = refreshIntervalMs;
    this.onError = onError;
    this.snapshot = createEmptySnapshot();
    this.lastRefreshAt = 0;
    this.refreshPromise = null;
    this.lastErrorAt = 0;
    this.binaryMetadataCache = new Map();
  }

  reportError(error) {
    if (!this.onError) {
      return;
    }

    const now = Date.now();
    if (now - this.lastErrorAt < ERROR_THROTTLE_MS) {
      return;
    }

    this.lastErrorAt = now;
    this.onError(error);
  }

  async refreshSnapshot() {
    if (this.platform !== 'win32') {
      return this.snapshot;
    }

    const payload = await executeProcessQuery('powershell.exe', WINDOWS_PROCESS_QUERY);
    this.snapshot = buildSnapshot(parseProcessQueryResponse(payload));
    this.lastRefreshAt = Date.now();
    return this.snapshot;
  }

  async getSnapshot() {
    if (this.platform !== 'win32') {
      return this.snapshot;
    }

    const now = Date.now();
    const hasSnapshot = this.lastRefreshAt > 0;
    const snapshotIsFresh = hasSnapshot && now - this.lastRefreshAt < this.refreshIntervalMs;

    if (snapshotIsFresh) {
      return this.snapshot;
    }

    if (this.refreshPromise) {
      return hasSnapshot ? this.snapshot : this.refreshPromise;
    }

    this.refreshPromise = this.refreshSnapshot()
      .catch(error => {
        this.reportError(error);
        return this.snapshot;
      })
      .finally(() => {
        this.refreshPromise = null;
      });

    return hasSnapshot ? this.snapshot : this.refreshPromise;
  }

  async getBinaryMetadata(executablePath) {
    if (this.platform !== 'win32' || !executablePath) {
      return null;
    }

    const cachedMetadata = this.binaryMetadataCache.get(executablePath);
    if (cachedMetadata && Date.now() - cachedMetadata.cachedAt < BINARY_METADATA_TTL_MS) {
      return cachedMetadata.value;
    }

    try {
      const payload = await executeProcessQuery('powershell.exe', buildBinaryMetadataQuery(executablePath));
      const parsed = payload ? JSON.parse(payload) : {};
      const metadata = {
        companyName: normalizeText(parsed.companyName),
        fileDescription: normalizeText(parsed.fileDescription),
        signatureStatus: normalizeText(parsed.signatureStatus),
        signerSubject: normalizeText(parsed.signerSubject),
      };
      this.binaryMetadataCache.set(executablePath, {
        cachedAt: Date.now(),
        value: metadata,
      });
      return metadata;
    } catch (error) {
      this.reportError(error);
      this.binaryMetadataCache.set(executablePath, {
        cachedAt: Date.now(),
        value: null,
      });
      return null;
    }
  }

  lookupPacket(packet, snapshot) {
    const candidates = deriveLocalEndpointCandidates(packet);

    for (const candidate of candidates) {
      if (candidate.protocol === 'TCP') {
        const exactMatch = snapshot.exactEndpoints.get(buildExactKey(candidate));
        if (exactMatch) {
          return exactMatch;
        }
      }

      const listenerMatch = snapshot.listenerEndpoints.get(buildListenerKey(candidate))
        ?? snapshot.listenerEndpoints.get(buildListenerKey({ ...candidate, localAddress: '*' }));
      if (listenerMatch) {
        return listenerMatch;
      }

      const localPortMatch = snapshot.localPortEndpoints.get(buildLocalPortKey(candidate));
      if (localPortMatch) {
        return localPortMatch;
      }
    }

    return null;
  }

  async enrichProcessEntry(entry) {
    if (!entry?.executablePath) {
      return entry;
    }

    const metadata = await this.getBinaryMetadata(entry.executablePath);
    if (!metadata) {
      return entry;
    }

    return {
      ...entry,
      ...metadata,
    };
  }

  async resolvePacket(packet) {
    if (this.platform !== 'win32') {
      return null;
    }

    try {
      const snapshot = await this.getSnapshot();
      const entry = this.lookupPacket(packet, snapshot);
      if (!entry) {
        return null;
      }
      return this.enrichProcessEntry(entry);
    } catch (error) {
      this.reportError(error);
      return null;
    }
  }
}
