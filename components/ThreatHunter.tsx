import React, { useState } from 'react';
import { SensorSummary, ThreatHuntingResponse } from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { runThreatHunt } from '../services/backendService';

interface ThreatHunterProps {
  backendBaseUrl: string;
  selectedSensorId: string | null;
  sensors: SensorSummary[];
}

export const ThreatHunter: React.FC<ThreatHunterProps> = ({
  backendBaseUrl,
  selectedSensorId,
  sensors,
}) => {
  const { t } = useLocalization();
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<ThreatHuntingResponse | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!question.trim()) {
      return;
    }

    setPending(true);
    setError(null);

    try {
      const response = await runThreatHunt(backendBaseUrl, question.trim(), selectedSensorId);
      setResult(response.result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : t('unknownError'));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white">{t('threatHuntTitle')}</h2>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('threatHuntDescription')}</p>
      </div>

      <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
        <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
          <div className="space-y-3">
            <label className="block text-sm font-medium text-gray-400">{t('threatHuntPrompt')}</label>
            <textarea
              value={question}
              onChange={event => setQuestion(event.target.value)}
              rows={4}
              className="w-full rounded-xl border border-gray-600 bg-gray-900 px-4 py-3 text-white focus:border-blue-500 focus:outline-none"
              placeholder={t('threatHuntPlaceholder')}
            />
            <div className="text-sm text-gray-500">
              {selectedSensorId
                ? t('threatHuntScopedSensor', { sensorName: sensors.find(sensor => sensor.id === selectedSensorId)?.name || selectedSensorId })
                : t('threatHuntScopedGlobal')}
            </div>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => void handleSubmit()}
              disabled={pending || !question.trim()}
              className="rounded-xl bg-blue-600 px-5 py-3 font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-700"
            >
              {pending ? t('threatHuntRunning') : t('threatHuntRun')}
            </button>
          </div>
        </div>
        {error && <div className="mt-4 text-sm text-red-300">{error}</div>}
      </section>

      {result && (
        <>
          <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
            <h3 className="text-xl font-semibold text-white">{t('threatHuntSummary')}</h3>
            <p className="mt-3 text-sm leading-6 text-gray-300">{result.summary}</p>
          </section>

          <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
            <h3 className="text-xl font-semibold text-white">{t('threatHuntSql')}</h3>
            <pre className="mt-4 overflow-x-auto rounded-xl bg-gray-900 p-4 text-xs text-green-300">{result.sql}</pre>
          </section>

          <section className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
            <div className="border-b border-gray-700/50 p-4">
              <h3 className="text-xl font-semibold text-white">{t('threatHuntResults')}</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-800/30">
                  <tr>
                    {(Object.keys(result.rows[0] ?? {}) || ['empty']).map(column => (
                      <th key={column} className="p-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                        {column}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {result.rows.length === 0 && (
                    <tr>
                      <td className="p-8 text-center text-gray-500">{t('threatHuntNoRows')}</td>
                    </tr>
                  )}
                  {result.rows.map((row, index) => (
                    <tr key={`${result.id}-${index}`} className="bg-[#161B22] text-sm hover:bg-[#1a212c]">
                      {Object.entries(row).map(([column, value]) => (
                        <td key={column} className="p-3 align-top text-gray-300">
                          <span className="break-all">{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '')}</span>
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
};
