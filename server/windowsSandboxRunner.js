import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';

const DEFAULT_GUEST_SHARE = 'C:\\Users\\WDAGUtilityAccount\\Desktop\\CerberusShare';
const POLL_INTERVAL_MS = 2000;
const SANDBOX_BOOT_GRACE_SECONDS = 240;
const MIN_RESULT_WAIT_SECONDS = 300;
const MIN_FREE_VIRTUAL_MEMORY_MB = 3072;

let sandboxQueue = Promise.resolve();

const fileExists = async targetPath => {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
};

const escapePowerShellString = value => String(value).replace(/'/g, "''");

const runPowerShell = (script, timeoutMs = 30000) => new Promise((resolve, reject) => {
  const child = spawn(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );

  let stdout = '';
  let stderr = '';
  const timeout = setTimeout(() => {
    child.kill();
    reject(new Error(`PowerShell command timed out after ${timeoutMs} ms.`));
  }, timeoutMs);

  child.stdout.on('data', chunk => {
    stdout += chunk.toString();
  });
  child.stderr.on('data', chunk => {
    stderr += chunk.toString();
  });
  child.on('error', error => {
    clearTimeout(timeout);
    reject(error);
  });
  child.on('exit', code => {
    clearTimeout(timeout);
    if (code === 0) {
      resolve(stdout.trim());
      return;
    }
    reject(new Error(stderr.trim() || stdout.trim() || `PowerShell exited with code ${code}.`));
  });
});

const queueSandboxRun = task => {
  const next = sandboxQueue.then(task, task);
  sandboxQueue = next.catch(() => undefined);
  return next;
};

const getSandboxExecutablePath = () => path.join(process.env.WINDIR || 'C:\\Windows', 'System32', 'WindowsSandbox.exe');

const safeParseJson = (value, fallback = null) => {
  try {
    return value ? JSON.parse(String(value).replace(/^\uFEFF/, '')) : fallback;
  } catch {
    return fallback;
  }
};

export const getWindowsSandboxAvailability = async () => {
  if (process.platform !== 'win32') {
    return {
      available: false,
      reason: 'Windows Sandbox is only available on Windows hosts.',
      executablePath: null,
      featureState: 'Unavailable',
    };
  }

  const executablePath = getSandboxExecutablePath();
  if (!(await fileExists(executablePath))) {
    return {
      available: false,
      reason: 'WindowsSandbox.exe was not found on this host.',
      executablePath,
      featureState: 'Unavailable',
    };
  }

  try {
    const featureState = await runPowerShell("(Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM').State", 45000);
    const normalizedState = featureState.trim();
    return {
      available: normalizedState.toLowerCase() === 'enabled',
      reason: normalizedState.toLowerCase() === 'enabled'
        ? null
        : `Windows Sandbox feature state is ${normalizedState || 'unknown'}.`,
      executablePath,
      featureState: normalizedState,
    };
  } catch (error) {
    return {
      available: true,
      reason: null,
      executablePath,
      queryWarning: error instanceof Error ? error.message : 'Unable to query Windows Sandbox feature state.',
      featureState: 'Unknown',
    };
  }
};

const getWindowsSandboxHostHealth = async () => {
  if (process.platform !== 'win32') {
    return {
      ok: false,
      reason: 'Windows Sandbox is only available on Windows hosts.',
      checks: {},
    };
  }

  try {
    const output = await runPowerShell(`
      $os = Get-CimInstance Win32_OperatingSystem
      $pageUsage = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
          name = $_.Name
          allocatedBaseSizeMb = [int]$_.AllocatedBaseSize
          currentUsageMb = [int]$_.CurrentUsage
          peakUsageMb = [int]$_.PeakUsage
          tempPageFile = [bool]$_.TempPageFile
        }
      })
      $pageSettings = @(Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
          name = $_.Name
          initialSizeMb = [int]$_.InitialSize
          maximumSizeMb = [int]$_.MaximumSize
        }
      })
      [pscustomobject]@{
        freePhysicalMemoryMb = [math]::Round([double]$os.FreePhysicalMemory / 1024, 0)
        freeVirtualMemoryMb = [math]::Round([double]$os.FreeVirtualMemory / 1024, 0)
        totalVisibleMemoryMb = [math]::Round([double]$os.TotalVisibleMemorySize / 1024, 0)
        totalVirtualMemoryMb = [math]::Round([double]$os.TotalVirtualMemorySize / 1024, 0)
        pageFileUsage = $pageUsage
        pageFileSettings = $pageSettings
      } | ConvertTo-Json -Depth 6 -Compress
    `, 30000);

    const payload = safeParseJson(output, {});
    const freePhysicalMemoryMb = Number(payload?.freePhysicalMemoryMb) || 0;
    const freeVirtualMemoryMb = Number(payload?.freeVirtualMemoryMb) || 0;
    const pageFileUsage = Array.isArray(payload?.pageFileUsage) ? payload.pageFileUsage : [];
    const pageFileSettings = Array.isArray(payload?.pageFileSettings) ? payload.pageFileSettings : [];
    const hasPageFile = pageFileUsage.length > 0 || pageFileSettings.length > 0;
    const warnings = [];

    if (!hasPageFile) {
      warnings.push('No Windows page file is configured on the host.');
    }
    if (freeVirtualMemoryMb > 0 && freeVirtualMemoryMb < MIN_FREE_VIRTUAL_MEMORY_MB) {
      warnings.push(`Only ${freeVirtualMemoryMb} MB of free virtual memory is currently available.`);
    }
    if (freePhysicalMemoryMb > 0 && freePhysicalMemoryMb < 4096) {
      warnings.push(`Only ${freePhysicalMemoryMb} MB of free physical memory is currently available.`);
    }

    const hardFailure = !hasPageFile || (freeVirtualMemoryMb > 0 && freeVirtualMemoryMb < MIN_FREE_VIRTUAL_MEMORY_MB);
    return {
      ok: !hardFailure,
      reason: hardFailure
        ? [
            !hasPageFile ? 'Windows Sandbox was blocked because no page file is configured on the host.' : null,
            freeVirtualMemoryMb > 0 && freeVirtualMemoryMb < MIN_FREE_VIRTUAL_MEMORY_MB
              ? `Free virtual memory is too low (${freeVirtualMemoryMb} MB).`
              : null,
          ].filter(Boolean).join(' ')
        : null,
      checks: {
        freePhysicalMemoryMb,
        freeVirtualMemoryMb,
        totalVisibleMemoryMb: Number(payload?.totalVisibleMemoryMb) || 0,
        totalVirtualMemoryMb: Number(payload?.totalVirtualMemoryMb) || 0,
        hasPageFile,
        pageFileUsage,
        pageFileSettings,
        warnings,
      },
    };
  } catch (error) {
    return {
      ok: true,
      reason: null,
      checks: {
        warnings: [
          error instanceof Error
            ? `Host health preflight could not be completed: ${error.message}`
            : 'Host health preflight could not be completed.',
        ],
      },
    };
  }
};

const buildSandboxBootstrapScript = ({ guestSharePath, guestSampleName, guestRuntimeSeconds }) => {
  const escapedSharePath = escapePowerShellString(guestSharePath);
  const escapedSampleName = escapePowerShellString(guestSampleName);

  return [
    "$ErrorActionPreference = 'Continue'",
    "$ProgressPreference = 'SilentlyContinue'",
    `$shareRoot = '${escapedSharePath}'`,
    `$samplePath = Join-Path $shareRoot '${escapedSampleName}'`,
    "$resultPath = Join-Path $shareRoot 'result.json'",
    "$transcriptPath = Join-Path $shareRoot 'session.log'",
    `$runtimeSeconds = ${guestRuntimeSeconds}`,
    "$watchPaths = @(",
    "  'C:\\Users\\WDAGUtilityAccount\\Desktop',",
    "  'C:\\Users\\WDAGUtilityAccount\\Documents',",
    "  'C:\\Users\\WDAGUtilityAccount\\Downloads',",
    "  $env:TEMP,",
    "  'C:\\Users\\WDAGUtilityAccount\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'",
    ")",
    '',
    'function Get-ProcessSnapshot {',
    '  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {',
    '    [pscustomobject]@{',
    '      processId = [int]$_.ProcessId',
    '      parentProcessId = [int]$_.ParentProcessId',
    '      name = $_.Name',
    '      executablePath = $_.ExecutablePath',
    '      commandLine = $_.CommandLine',
    '    }',
    '  }',
    '}',
    '',
    'function Get-TcpSnapshot {',
    '  @(Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {',
    '    [pscustomobject]@{',
    '      localAddress = $_.LocalAddress',
    '      localPort = [int]$_.LocalPort',
    '      remoteAddress = $_.RemoteAddress',
    '      remotePort = [int]$_.RemotePort',
    '      state = $_.State.ToString()',
    '      owningProcess = [int]$_.OwningProcess',
    '    }',
    '  })',
    '}',
    '',
    'function Get-UdpSnapshot {',
    '  @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {',
    '    [pscustomobject]@{',
    '      localAddress = $_.LocalAddress',
    '      localPort = [int]$_.LocalPort',
    '      owningProcess = [int]$_.OwningProcess',
    '    }',
    '  })',
    '}',
    '',
    'function Get-FileSnapshot([string[]]$paths) {',
    '  $results = @()',
    '  foreach ($root in $paths) {',
    '    if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root)) {',
    '      $results += Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 250 | ForEach-Object {',
    '        [pscustomobject]@{',
    '          path = $_.FullName',
    '          length = [int64]$_.Length',
    '          lastWriteTimeUtc = $_.LastWriteTimeUtc.ToString("o")',
    '        }',
    '      }',
    '    }',
    '  }',
    '  return $results',
    '}',
    '',
    'function Get-RunKeySnapshot {',
    '  $entries = @()',
    "  foreach ($registryPath in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')) {",
    '    if (Test-Path $registryPath) {',
    '      $item = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue',
    '      if ($null -ne $item) {',
    '        foreach ($property in $item.PSObject.Properties) {',
    "          if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {",
    '            $entries += [pscustomobject]@{',
    '              path = $registryPath',
    '              name = $property.Name',
    '              value = [string]$property.Value',
    '            }',
    '          }',
    '        }',
    '      }',
    '    }',
    '  }',
    '  return $entries',
    '}',
    '',
    'function Get-ServiceSnapshot {',
    '  @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {',
    '    [pscustomobject]@{',
    '      name = $_.Name',
    '      displayName = $_.DisplayName',
    '      state = $_.State',
    '      startMode = $_.StartMode',
    '      pathName = $_.PathName',
    '    }',
    '  })',
    '}',
    '',
    'function New-JsonResult([hashtable]$payload) {',
    '  $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8',
    '}',
    '',
    '$startedAt = [DateTime]::UtcNow.ToString("o")',
    '$baselineProcesses = @(Get-ProcessSnapshot)',
    '$baselineProcessIds = @($baselineProcesses.processId)',
    '$baselineFiles = @(Get-FileSnapshot $watchPaths)',
    '$baselineFileIndex = @{}',
    '$normalizedShareRoot = $shareRoot.ToLowerInvariant()',
    'foreach ($file in $baselineFiles) { $baselineFileIndex[$file.path] = "$($file.length)|$($file.lastWriteTimeUtc)" }',
    '$baselineServices = @(Get-ServiceSnapshot)',
    '$baselineServiceNames = @($baselineServices.name)',
    '$baselineRunKeys = @(Get-RunKeySnapshot)',
    '$baselineRunKeyIndex = @{}',
    'foreach ($entry in $baselineRunKeys) { $baselineRunKeyIndex["$($entry.path)|$($entry.name)"] = $entry.value }',
    '$execution = [ordered]@{ status = "not_executed"; mode = "unknown"; processId = $null; processName = $null; commandLine = $null; error = $null }',
    '',
    'try {',
    '  Start-Transcript -Path $transcriptPath -Force | Out-Null',
    '  $extension = [IO.Path]::GetExtension($samplePath).ToLowerInvariant()',
    '  switch ($extension) {',
    "    '.exe' { $process = Start-Process -FilePath $samplePath -PassThru; $execution.status = 'started'; $execution.mode = 'native'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = $samplePath }",
    "    '.com' { $process = Start-Process -FilePath $samplePath -PassThru; $execution.status = 'started'; $execution.mode = 'native'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = $samplePath }",
    `    '.ps1' { $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', $samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'powershell'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "powershell.exe -ExecutionPolicy Bypass -File ""$samplePath""" }`,
    `    '.bat' { $process = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'cmd'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "cmd.exe /c ""$samplePath""" }`,
    `    '.cmd' { $process = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'cmd'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "cmd.exe /c ""$samplePath""" }`,
    `    '.vbs' { $process = Start-Process -FilePath 'wscript.exe' -ArgumentList @($samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'wscript'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "wscript.exe ""$samplePath""" }`,
    `    '.js' { $process = Start-Process -FilePath 'wscript.exe' -ArgumentList @($samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'wscript'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "wscript.exe ""$samplePath""" }`,
    `    '.jse' { $process = Start-Process -FilePath 'wscript.exe' -ArgumentList @($samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'wscript'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "wscript.exe ""$samplePath""" }`,
    `    '.wsf' { $process = Start-Process -FilePath 'wscript.exe' -ArgumentList @($samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'wscript'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "wscript.exe ""$samplePath""" }`,
    `    '.hta' { $process = Start-Process -FilePath 'mshta.exe' -ArgumentList @($samplePath) -PassThru; $execution.status = 'started'; $execution.mode = 'mshta'; $execution.processId = [int]$process.Id; $execution.processName = $process.ProcessName; $execution.commandLine = "mshta.exe ""$samplePath""" }`,
    "    default { $execution.status = 'skipped'; $execution.mode = 'unsupported'; $execution.error = \"Unsupported file extension: $extension\" }",
    '  }',
    '} catch {',
    "  $execution.status = 'failed'",
    "  $execution.error = $_.Exception.Message",
    '}',
    '',
    'if ($execution.status -eq "started") {',
    '  Start-Sleep -Seconds $runtimeSeconds',
    '} else {',
    '  Start-Sleep -Seconds ([Math]::Min($runtimeSeconds, 10))',
    '}',
    '',
    '$afterProcesses = @(Get-ProcessSnapshot)',
    '$processTree = @()',
    'if ($execution.processId) {',
    '  $queue = New-Object System.Collections.Queue',
    '  $queue.Enqueue([int]$execution.processId)',
    '  $visited = @{}',
    '  while ($queue.Count -gt 0) {',
    '    $currentPid = [int]$queue.Dequeue()',
    '    if ($visited.ContainsKey($currentPid)) { continue }',
    '    $visited[$currentPid] = $true',
    '    $matches = @($afterProcesses | Where-Object { $_.processId -eq $currentPid -or $_.parentProcessId -eq $currentPid })',
    '    foreach ($match in $matches) {',
    '      if ($processTree.processId -notcontains $match.processId) {',
    '        $processTree += $match',
    '      }',
    '      if ($match.processId -ne $currentPid) { $queue.Enqueue([int]$match.processId) }',
    '    }',
    '  }',
    '}',
    '$newProcesses = @($afterProcesses | Where-Object { $_.processId -notin $baselineProcessIds })',
    '$interestingProcesses = @($processTree + $newProcesses | Sort-Object processId -Unique | Select-Object -First 50)',
    '$interestingProcessIds = @($interestingProcesses.processId)',
    'if ($execution.processId -and $interestingProcessIds -notcontains $execution.processId) { $interestingProcessIds += [int]$execution.processId }',
    '$tcpConnections = @(Get-TcpSnapshot | Where-Object { $_.owningProcess -in $interestingProcessIds } | Select-Object -First 50)',
    '$udpConnections = @(Get-UdpSnapshot | Where-Object { $_.owningProcess -in $interestingProcessIds } | Select-Object -First 50)',
    '$afterFiles = @(Get-FileSnapshot $watchPaths)',
    '$addedFiles = @()',
    '$modifiedFiles = @()',
    'foreach ($file in $afterFiles) {',
    '  if ($file.path.ToLowerInvariant().StartsWith($normalizedShareRoot)) { continue }',
    '  $signature = "$($file.length)|$($file.lastWriteTimeUtc)"',
    '  if (-not $baselineFileIndex.ContainsKey($file.path)) {',
    '    $addedFiles += $file',
    '  } elseif ($baselineFileIndex[$file.path] -ne $signature) {',
    '    $modifiedFiles += $file',
    '  }',
    '}',
    '$afterServices = @(Get-ServiceSnapshot)',
    '$createdServices = @($afterServices | Where-Object { $_.name -notin $baselineServiceNames } | Select-Object -First 25)',
    '$afterRunKeys = @(Get-RunKeySnapshot)',
    '$addedRunKeys = @()',
    'foreach ($entry in $afterRunKeys) {',
    '  $compositeKey = "$($entry.path)|$($entry.name)"',
    '  if (-not $baselineRunKeyIndex.ContainsKey($compositeKey) -or $baselineRunKeyIndex[$compositeKey] -ne $entry.value) {',
    '    $addedRunKeys += $entry',
    '  }',
    '}',
    'if ($execution.processId) {',
    '  Stop-Process -Id $execution.processId -Force -ErrorAction SilentlyContinue',
    '}',
    '$result = [ordered]@{',
    "  status = 'completed'",
    "  platform = 'windows_sandbox'",
    '  startedAt = $startedAt',
    '  finishedAt = [DateTime]::UtcNow.ToString("o")',
    '  runtimeSeconds = $runtimeSeconds',
    '  execution = $execution',
    '  processes = @($interestingProcesses)',
    '  network = [ordered]@{ tcp = @($tcpConnections); udp = @($udpConnections) }',
    '  files = [ordered]@{ added = @($addedFiles | Select-Object -First 50); modified = @($modifiedFiles | Select-Object -First 50) }',
    '  services = [ordered]@{ created = @($createdServices) }',
    '  registry = [ordered]@{ runKeys = @($addedRunKeys | Select-Object -First 25) }',
    '  transcriptPath = $transcriptPath',
    '}',
    'New-JsonResult $result',
    'try { Stop-Transcript | Out-Null } catch { }',
    'Start-Sleep -Seconds 2',
    'exit 0',
  ].join('\r\n');
};

const buildWsbConfiguration = ({ hostSharePath, guestSharePath, bootstrapGuestPath }) => [
  '<Configuration>',
  '  <vGPU>Disable</vGPU>',
  '  <AudioInput>Disable</AudioInput>',
  '  <VideoInput>Disable</VideoInput>',
  '  <ProtectedClient>Enable</ProtectedClient>',
  '  <ClipboardRedirection>Disable</ClipboardRedirection>',
  '  <PrinterRedirection>Disable</PrinterRedirection>',
  '  <Networking>Enable</Networking>',
  '  <MappedFolders>',
  '    <MappedFolder>',
  `      <HostFolder>${hostSharePath}</HostFolder>`,
  `      <SandboxFolder>${guestSharePath}</SandboxFolder>`,
  '      <ReadOnly>false</ReadOnly>',
  '    </MappedFolder>',
  '  </MappedFolders>',
  '  <LogonCommand>',
  `    <Command>powershell.exe -ExecutionPolicy Bypass -File "${bootstrapGuestPath}"</Command>`,
  '  </LogonCommand>',
  '</Configuration>',
].join('\r\n');

const launchSandboxWorkspace = async ({ wsbPath }) => {
  const escapedWsbPath = escapePowerShellString(wsbPath);
  await runPowerShell(`Start-Process -FilePath '${escapedWsbPath}'`, 15000);
};

const listSandboxProcessIds = async () => {
  try {
    const output = await runPowerShell(
      "@(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'WindowsSandbox*' -or $_.ProcessName -like 'vmmemWindowsSandbox' } | Select-Object -ExpandProperty Id) -join ','",
      15000
    );
    return output
      .split(',')
      .map(value => Number.parseInt(value.trim(), 10))
      .filter(value => Number.isFinite(value));
  } catch {
    return [];
  }
};

const killSandboxProcessTree = async ({ baselinePids = [] } = {}) => {
  const activePids = await listSandboxProcessIds();
  const targetPids = activePids.filter(pid => !baselinePids.includes(pid));
  if (targetPids.length === 0) {
    return;
  }

  for (const pid of targetPids) {
    try {
      await runPowerShell(`Stop-Process -Id ${pid} -Force -ErrorAction SilentlyContinue`, 15000);
    } catch {
      try {
        await runPowerShell(`cmd.exe /c taskkill /PID ${pid} /T /F`, 15000);
      } catch {
        // Ignore teardown failures. A later pass may still catch the process.
      }
    }
  }

  await new Promise(resolve => {
    setTimeout(resolve, 4000);
  });
};

const waitForResultFile = async ({ resultPath, timeoutMs }) => {
  const timeoutAt = Date.now() + timeoutMs;

  while (Date.now() < timeoutAt) {
    if (await fileExists(resultPath)) {
      try {
        const rawText = await fs.readFile(resultPath, 'utf8');
        const payload = JSON.parse(rawText.replace(/^\uFEFF/, ''));
        return payload;
      } catch {
        // The guest may still be writing the file. Retry on the next poll.
      }
    }

    await new Promise(resolve => {
      setTimeout(resolve, POLL_INTERVAL_MS);
    });
  }

  throw new Error(`Windows Sandbox analysis timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
};

const getSandboxResultTimeoutMs = runtimeSeconds => {
  const normalizedRuntimeSeconds = Math.max(10, Number(runtimeSeconds) || 0);
  const waitSeconds = Math.max(
    normalizedRuntimeSeconds + SANDBOX_BOOT_GRACE_SECONDS,
    MIN_RESULT_WAIT_SECONDS
  );
  return waitSeconds * 1000;
};

export const runWindowsSandboxAnalysis = ({
  sampleDirectory,
  stagedFilePath,
  fileName,
  runtimeSeconds,
  onLog,
  onStageUpdate,
}) => queueSandboxRun(async () => {
  const availability = await getWindowsSandboxAvailability();
  if (!availability.available) {
    onLog?.('WARN', 'Windows Sandbox dynamic analysis skipped.', {
      reason: availability.reason,
      featureState: availability.featureState,
    });
    return {
      status: 'skipped',
      mode: 'windows_sandbox',
      reason: availability.reason,
      featureState: availability.featureState,
      executablePath: availability.executablePath,
    };
  }

  const hostHealth = await getWindowsSandboxHostHealth();
  if (!hostHealth.ok) {
    onLog?.('WARN', 'Windows Sandbox dynamic analysis blocked by host preflight.', {
      reason: hostHealth.reason,
      checks: hostHealth.checks,
      featureState: availability.featureState,
    });
    return {
      status: 'failed',
      mode: 'windows_sandbox',
      reason: hostHealth.reason,
      hostHealth: hostHealth.checks,
      executablePath: availability.executablePath,
      featureState: availability.featureState,
      queryWarning: availability.queryWarning ?? null,
    };
  }

  const baselinePids = await listSandboxProcessIds();
  if (baselinePids.length > 0) {
    return {
      status: 'failed',
      mode: 'windows_sandbox',
      reason: 'A Windows Sandbox instance is already running on the host. Close it before starting a new Cerberus Lab detonation.',
      existingSandboxPids: baselinePids,
      executablePath: availability.executablePath,
      featureState: availability.featureState,
      queryWarning: availability.queryWarning ?? null,
    };
  }

  const runId = `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  const dynamicRoot = path.join(sampleDirectory, 'windows-sandbox', runId);
  const shareRoot = path.join(dynamicRoot, 'share');
  const guestSampleName = path.basename(fileName);
  const resultPath = path.join(shareRoot, 'result.json');
  const bootstrapHostPath = path.join(shareRoot, 'bootstrap.ps1');
  const bootstrapGuestPath = `${DEFAULT_GUEST_SHARE}\\bootstrap.ps1`;
  const wsbPath = path.join(dynamicRoot, 'cerberus-lab.wsb');
  const guestSamplePath = path.join(shareRoot, guestSampleName);

  await fs.mkdir(shareRoot, { recursive: true });
  await fs.copyFile(stagedFilePath, guestSamplePath);
  await fs.writeFile(
    bootstrapHostPath,
    buildSandboxBootstrapScript({
      guestSharePath: DEFAULT_GUEST_SHARE,
      guestSampleName,
      guestRuntimeSeconds: runtimeSeconds,
    }),
    'utf8'
  );
  await fs.writeFile(
    wsbPath,
    buildWsbConfiguration({
      hostSharePath: shareRoot,
      guestSharePath: DEFAULT_GUEST_SHARE,
      bootstrapGuestPath,
    }),
    'utf8'
  );

  onLog?.('INFO', 'Launching Windows Sandbox dynamic analysis.', {
    shareRoot,
    wsbPath,
    runtimeSeconds,
  });
  onStageUpdate?.('launching_sandbox', 'Launching Windows Sandbox guest.');

  try {
    await launchSandboxWorkspace({ wsbPath });
    onStageUpdate?.('guest_execution', 'Running sample inside Windows Sandbox.');
    const resultTimeoutMs = getSandboxResultTimeoutMs(runtimeSeconds);
    onLog?.('INFO', 'Waiting for Windows Sandbox analysis result.', {
      resultPath,
      timeoutSeconds: Math.round(resultTimeoutMs / 1000),
      runtimeSeconds,
    });
    const result = await waitForResultFile({
      resultPath,
      timeoutMs: resultTimeoutMs,
    });
    onStageUpdate?.('collecting_results', 'Collecting results from Windows Sandbox.');
    return {
      ...result,
      workspaceRoot: dynamicRoot,
      shareRoot,
      resultPath,
      bootstrapHostPath,
      wsbPath,
    };
  } finally {
    await killSandboxProcessTree({ baselinePids });
  }
});
