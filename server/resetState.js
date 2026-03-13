import fs from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const dataDirectory = path.join(projectRoot, 'data');
const distDirectory = path.join(projectRoot, 'dist');

const removeIfExists = (targetPath) => {
  if (fs.existsSync(targetPath)) {
    fs.rmSync(targetPath, { recursive: true, force: true });
    return true;
  }
  return false;
};

const removedData = removeIfExists(dataDirectory);
const removedDist = removeIfExists(distDirectory);

fs.mkdirSync(dataDirectory, { recursive: true });

const { directories, getServerConfiguration } = await import('./db.js');
const config = getServerConfiguration();

console.log(JSON.stringify({
  ok: true,
  removedData,
  removedDist,
  recreated: {
    dataDirectory: directories.dataDirectory,
    pcapDirectory: directories.pcapDirectory,
    replayDirectory: directories.replayDirectory,
    databasePath: directories.databasePath,
  },
  config: {
    llmProvider: config.llmProvider,
    sensorId: config.sensorId,
    sensorName: config.sensorName,
    captureInterface: config.captureInterface,
    captureFilter: config.captureFilter,
    providerSettings: {
      lmstudio: config.providerSettings.lmstudio,
    },
  },
}, null, 2));
