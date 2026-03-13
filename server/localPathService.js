import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const validateLocalPath = (targetPath) => {
  if (typeof targetPath !== 'string' || !targetPath.trim()) {
    throw new Error('A valid path is required.');
  }

  const resolvedPath = path.resolve(targetPath.trim());
  if (!path.isAbsolute(resolvedPath)) {
    throw new Error('Only absolute local paths can be opened.');
  }

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${resolvedPath}`);
  }

  return resolvedPath;
};

const spawnDetached = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      detached: true,
      shell: false,
      stdio: 'ignore',
      windowsHide: true,
    });

    child.on('error', reject);
    child.unref();
    resolve();
  });

export const revealLocalPath = async (targetPath) => {
  const resolvedPath = validateLocalPath(targetPath);
  const stats = fs.statSync(resolvedPath);
  const platform = os.platform();

  if (platform === 'win32') {
    if (stats.isDirectory()) {
      await spawnDetached('explorer.exe', [resolvedPath]);
    } else {
      await spawnDetached('explorer.exe', [`/select,${resolvedPath}`]);
    }
    return resolvedPath;
  }

  if (platform === 'darwin') {
    await spawnDetached('open', stats.isDirectory() ? [resolvedPath] : ['-R', resolvedPath]);
    return resolvedPath;
  }

  if (platform === 'linux') {
    await spawnDetached('xdg-open', [stats.isDirectory() ? resolvedPath : path.dirname(resolvedPath)]);
    return resolvedPath;
  }

  throw new Error(`Opening local paths is not supported on platform: ${platform}`);
};
