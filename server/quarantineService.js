import fs from 'node:fs/promises';
import path from 'node:path';

const quarantineRoot = path.resolve(process.cwd(), 'data', 'sandbox-quarantine');
const MAX_SIDECAR_FILES = 32;

const sanitizeFileName = value => value.replace(/[^a-zA-Z0-9._-]+/g, '_');
const sanitizeRelativeBundlePath = value =>
  String(value || '')
    .split(/[\\/]+/)
    .filter(Boolean)
    .map(segment => sanitizeFileName(segment))
    .filter(Boolean)
    .join(path.sep);

export const getQuarantineRoot = () => quarantineRoot;

export const stageSampleInQuarantine = async ({ sourcePath, fileName, sha256, buffer, sidecarFiles = [] }) => {
  const sampleDirectory = path.join(quarantineRoot, sha256);
  const stagedFileName = sanitizeFileName(fileName);
  const stagedFilePath = path.join(sampleDirectory, stagedFileName);
  const manifestPath = path.join(sampleDirectory, 'manifest.json');
  const bundleEntries = [];
  const seenBundlePaths = new Set();

  await fs.mkdir(sampleDirectory, { recursive: true });
  await fs.writeFile(stagedFilePath, buffer);

  bundleEntries.push({
    role: 'primary',
    sourcePath,
    stagedPath: stagedFilePath,
    fileName,
    relativePath: stagedFileName,
  });
  seenBundlePaths.add(stagedFileName.toLowerCase());

  for (const sidecar of sidecarFiles.slice(0, MAX_SIDECAR_FILES)) {
    const relativePath = sanitizeRelativeBundlePath(sidecar.relativePath || sidecar.fileName || path.basename(sidecar.sourcePath || ''));
    if (!relativePath) {
      continue;
    }

    const normalizedRelativePath = relativePath.toLowerCase();
    if (seenBundlePaths.has(normalizedRelativePath)) {
      continue;
    }

    const stagedSidecarPath = path.join(sampleDirectory, relativePath);
    await fs.mkdir(path.dirname(stagedSidecarPath), { recursive: true });
    await fs.copyFile(sidecar.sourcePath, stagedSidecarPath);
    seenBundlePaths.add(normalizedRelativePath);
    bundleEntries.push({
      role: 'sidecar',
      sourcePath: sidecar.sourcePath,
      stagedPath: stagedSidecarPath,
      fileName: sidecar.fileName || path.basename(sidecar.sourcePath),
      relativePath,
    });
  }

  await fs.writeFile(
    manifestPath,
    JSON.stringify(
      {
        sourcePath,
        stagedFilePath,
        fileName,
        sha256,
        bundleFiles: bundleEntries,
        stagedAt: new Date().toISOString(),
      },
      null,
      2
    ),
    'utf8'
  );

  return {
    sampleDirectory,
    stagedFilePath,
    manifestPath,
    bundleFiles: bundleEntries,
  };
};
