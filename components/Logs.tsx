import React, { useState } from 'react';
import { LogEntry, LogLevel, SensorSummary } from '../types';
import { useLocalization } from '../hooks/useLocalization';

interface LogsProps {
  logs: LogEntry[];
  sensors: SensorSummary[];
  selectedSensorId: string | null;
  onSelectSensor: (sensorId: string | null) => void;
}

const getLogLevelColor = (level: LogLevel): string => {
  switch (level) {
    case LogLevel.INFO:
      return 'text-blue-400';
    case LogLevel.WARN:
      return 'text-yellow-400';
    case LogLevel.ERROR:
      return 'text-orange-400';
    case LogLevel.CRITICAL:
      return 'text-red-500 font-bold';
    default:
      return 'text-gray-400';
  }
};

const formatTimestamp = (isoString: string): string => {
  const date = new Date(isoString);
  const hours = date.getHours().toString().padStart(2, '0');
  const minutes = date.getMinutes().toString().padStart(2, '0');
  const seconds = date.getSeconds().toString().padStart(2, '0');
  const milliseconds = date.getMilliseconds().toString().padStart(3, '0');
  return `${hours}:${minutes}:${seconds}.${milliseconds}`;
};

const LogRow: React.FC<{ log: LogEntry }> = ({ log }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <>
      <tr className="cursor-pointer bg-gray-800 transition-colors duration-200 hover:bg-gray-700/50" onClick={() => setIsExpanded(!isExpanded)}>
        <td className="p-3 text-sm whitespace-nowrap text-gray-500">{formatTimestamp(log.timestamp)}</td>
        <td className={`p-3 text-sm font-semibold whitespace-nowrap ${getLogLevelColor(log.level)}`}>{log.level}</td>
        <td className="p-3 text-sm text-gray-400">{log.sensorName || '-'}</td>
        <td className="w-full p-3 text-sm text-gray-300">{log.message}</td>
        <td className="p-3 text-center text-sm text-gray-500">
          {log.details && <span className="text-gray-400">{isExpanded ? '▼' : '►'}</span>}
        </td>
      </tr>
      {isExpanded && log.details && (
        <tr className="bg-gray-800/50">
          <td colSpan={5} className="p-4">
            <pre className="overflow-x-auto rounded-md bg-gray-900 p-4 font-mono text-xs text-green-300">
              {JSON.stringify(log.details, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
};

export const Logs: React.FC<LogsProps> = ({ logs, sensors, selectedSensorId, onSelectSensor }) => {
  const { t } = useLocalization();
  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="mb-2 text-3xl font-bold text-white">{t('logsTitle')}</h2>
          <p className="text-sm text-gray-400">{t('logsDescription')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSelectSensor(null)}
            className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
              selectedSensorId === null ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
            }`}
          >
            {t('fleetAllSensors')}
          </button>
          {sensors.map(sensor => (
            <button
              key={sensor.id}
              onClick={() => onSelectSensor(sensor.id)}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                selectedSensorId === sensor.id ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
              }`}
            >
              {sensor.name}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-lg bg-gray-800 shadow-xl">
        <div className="overflow-x-auto max-h-[75vh]">
          <table className="w-full">
            <thead className="sticky top-0 bg-gray-700">
              <tr>
                <th className="w-32 p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('colTimestamp')}</th>
                <th className="w-32 p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('colLevel')}</th>
                <th className="w-48 p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('fleetColSensor')}</th>
                <th className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-300">{t('colMessage')}</th>
                <th className="w-16 p-3 text-center text-xs font-medium uppercase tracking-wider text-gray-300">{t('colDetails')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {logs.length > 0 ? (
                logs.map(log => <LogRow key={log.id} log={log} />)
              ) : (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-gray-500">
                    {t('noLogsYet')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
