import React from 'react';
import { FleetStatusPayload, SensorSummary } from '../types';
import { useLocalization } from '../hooks/useLocalization';

interface FleetManagementProps {
  sensors: SensorSummary[];
  fleetStatus: FleetStatusPayload;
  selectedSensorId: string | null;
  onSelectSensor: (sensorId: string | null) => void;
}

const formatTimestamp = (value: string | null, localeCode: string) => {
  if (!value) {
    return '-';
  }

  try {
    return new Intl.DateTimeFormat(localeCode, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(value));
  } catch {
    return value;
  }
};

export const FleetManagement: React.FC<FleetManagementProps> = ({
  sensors,
  fleetStatus,
  selectedSensorId,
  onSelectSensor,
}) => {
  const { t } = useLocalization();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('fleetTitle')}</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('fleetDescription')}</p>
        </div>
        <div className="rounded-xl border border-gray-700 bg-[#161B22] px-4 py-3 text-sm text-gray-300">
          <div>{t('fleetModeLabel')}: <span className="font-semibold text-white">{fleetStatus.deploymentMode}</span></div>
          <div className="mt-1">{t('fleetSensorsConnected')}: <span className="font-semibold text-white">{fleetStatus.connectedSensors}</span></div>
        </div>
      </div>

      <div className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-5">
        <div className="flex flex-wrap items-center gap-3">
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

      <div className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
        <div className="border-b border-gray-700/50 p-4">
          <h3 className="text-xl font-semibold text-white">{t('fleetSensorsTable')}</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-800/30">
              <tr>
                {['fleetColSensor', 'fleetColMode', 'fleetColStatus', 'fleetColCapture', 'packetsProcessedCardTitle', 'threatsDetectedCardTitle', 'blockedDecisionsCardTitle', 'fleetColLastSeen'].map(header => (
                  <th key={header} className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                    {t(header)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {sensors.length === 0 && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-gray-500">{t('fleetNoSensors')}</td>
                </tr>
              )}
              {sensors.map(sensor => (
                <tr key={sensor.id} className="bg-[#161B22] text-sm hover:bg-[#1a212c]">
                  <td className="p-3">
                    <div className="font-semibold text-white">{sensor.name}</div>
                    <div className="text-xs text-gray-500">{sensor.id}</div>
                  </td>
                  <td className="p-3 text-gray-300">{sensor.mode}</td>
                  <td className="p-3">
                    <span className={`inline-flex rounded-full px-2 py-1 text-xs font-semibold ${
                      sensor.connected ? 'bg-emerald-500/15 text-emerald-200' : 'bg-red-500/15 text-red-200'
                    }`}>
                      {sensor.connected ? t('connectedStatus') : t('disconnectedStatus')}
                    </span>
                  </td>
                  <td className="p-3 text-gray-300">{sensor.captureRunning ? t('activeStatus') : t('stoppedStatus')}</td>
                  <td className="p-3 text-blue-300">{sensor.packetsProcessed.toLocaleString()}</td>
                  <td className="p-3 text-orange-300">{sensor.threatsDetected.toLocaleString()}</td>
                  <td className="p-3 text-red-300">{sensor.blockedDecisions.toLocaleString()}</td>
                  <td className="p-3 text-gray-400">{formatTimestamp(sensor.lastSeenAt, t('localeCode'))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
