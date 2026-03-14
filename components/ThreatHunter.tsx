import React, { useState } from 'react';
import { SensorSummary, ThreatHuntingResponse } from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { runThreatHunt } from '../services/backendService';

interface ThreatHunterProps {
  backendBaseUrl: string;
  selectedSensorId: string | null;
  sensors: SensorSummary[];
  onBeforeRun?: () => Promise<unknown>;
}

interface ThreatHuntExampleDefinition {
  key: string;
  categoryDe: string;
  categoryEn: string;
  fallbackDe: string;
  fallbackEn: string;
}

const EXAMPLE_DEFINITIONS: ThreatHuntExampleDefinition[] = [
  { key: 'threatHuntExample1', categoryDe: 'Firewall', categoryEn: 'Firewall', fallbackDe: 'Zeig mir alle blockierten IPs der letzten 24 Stunden.', fallbackEn: 'Show me all blocked IPs from the last 24 hours.' },
  { key: 'threatHuntExample2', categoryDe: 'Prozess', categoryEn: 'Process', fallbackDe: 'Zeig mir alle Verbindungen vom Prozess opera.exe.', fallbackEn: 'Show all connections from process opera.exe.' },
  { key: 'threatHuntExample3', categoryDe: 'Sandbox', categoryEn: 'Sandbox', fallbackDe: 'Welche Dateien wurden in der Sandbox als suspicious oder malicious bewertet?', fallbackEn: 'Which files were rated suspicious or malicious in the sandbox?' },
  { key: 'threatHuntExample4', categoryDe: 'Sandbox', categoryEn: 'Sandbox', fallbackDe: 'Liste die letzten 20 Sandbox-Analysen mit Dateiname, Verdict und Score.', fallbackEn: 'List the last 20 sandbox analyses with file name, verdict and score.' },
  { key: 'threatHuntExample5', categoryDe: 'Angriffe', categoryEn: 'Attacks', fallbackDe: 'Zeig mir alle Ereignisse mit attackType brute_force.', fallbackEn: 'Show all events with attackType brute_force.' },
  { key: 'threatHuntExample6', categoryDe: 'Ports', categoryEn: 'Ports', fallbackDe: 'Welche Quell-IPs hatten Verbindungen zu Port 22 oder 3389?', fallbackEn: 'Which source IPs connected to port 22 or 3389?' },
  { key: 'threatHuntExample7', categoryDe: 'Verdacht', categoryEn: 'Suspicious', fallbackDe: 'Zeig mir verdaechtigen Verkehr der letzten 2 Stunden.', fallbackEn: 'Show suspicious traffic from the last 2 hours.' },
  { key: 'threatHuntExample8', categoryDe: 'Prozess', categoryEn: 'Process', fallbackDe: 'Welche Prozesse hatten Verbindungen zu Port 5353?', fallbackEn: 'Which processes had connections to port 5353?' },
  { key: 'threatHuntExample9', categoryDe: 'LLM', categoryEn: 'LLM', fallbackDe: 'Zeig mir alle Traffic-Eintraege mit decision source llm.', fallbackEn: 'Show all traffic entries with decision source llm.' },
  { key: 'threatHuntExample10', categoryDe: 'Firewall', categoryEn: 'Firewall', fallbackDe: 'Welche Quell-IPs wurden mehr als einmal blockiert?', fallbackEn: 'Which source IPs were blocked more than once?' },
  { key: 'threatHuntExample11', categoryDe: 'Fehler', categoryEn: 'Failures', fallbackDe: 'Liste alle CAPE- oder Cerberus-Lab-Analysen, die fehlgeschlagen sind.', fallbackEn: 'List all CAPE or Cerberus Lab analyses that failed.' },
  { key: 'threatHuntExample12', categoryDe: 'Sandbox', categoryEn: 'Sandbox', fallbackDe: 'Zeig mir heute die hoechsten Sandbox-Scores.', fallbackEn: 'Show the highest sandbox scores from today.' },
  { key: 'threatHuntExample13', categoryDe: 'Dateien', categoryEn: 'Files', fallbackDe: 'Welche Dateien wurden vom Prozess msedge.exe analysiert?', fallbackEn: 'Which files were analyzed from process msedge.exe?' },
  { key: 'threatHuntExample14', categoryDe: 'Logs', categoryEn: 'Logs', fallbackDe: 'Zeig mir alle kritischen Log-Eintraege von heute.', fallbackEn: 'Show all critical log entries from today.' },
  { key: 'threatHuntExample15', categoryDe: 'PCAP', categoryEn: 'PCAP', fallbackDe: 'Welche PCAP-Artefakte wurden fuer other oder malicious_payload exportiert?', fallbackEn: 'Which PCAP artifacts were exported for other or malicious_payload?' },
  { key: 'threatHuntExample16', categoryDe: 'UDP', categoryEn: 'UDP', fallbackDe: 'Zeig mir verdaechtigen UDP-Verkehr von heute.', fallbackEn: 'Show suspicious UDP traffic from today.' },
  { key: 'threatHuntExample17', categoryDe: 'Ports', categoryEn: 'Ports', fallbackDe: 'Welche Ziel-Ports wurden am haeufigsten blockiert?', fallbackEn: 'Which destination ports were most often blocked?' },
  { key: 'threatHuntExample18', categoryDe: 'Sensor', categoryEn: 'Sensor', fallbackDe: 'Zeig mir Verkehr fuer den Sensor Windows Lab Sensor aus der letzten Stunde.', fallbackEn: 'Show traffic for sensor Windows Lab Sensor from the last hour.' },
  { key: 'threatHuntExample19', categoryDe: 'Cache', categoryEn: 'Cache', fallbackDe: 'Welche verdaechtigen Ereignisse kamen von decision source cache?', fallbackEn: 'Which suspicious events came from decision source cache?' },
  { key: 'threatHuntExample20', categoryDe: 'Sandbox', categoryEn: 'Sandbox', fallbackDe: 'Zeig mir Dateinamen, Verdicts und Zeitstempel der neuesten Sandbox-Analysen.', fallbackEn: 'Show file names, verdicts and timestamps of the latest sandbox analyses.' },
];

export const ThreatHunter: React.FC<ThreatHunterProps> = ({
  backendBaseUrl,
  selectedSensorId,
  sensors,
  onBeforeRun,
}) => {
  const { t, currentLanguage } = useLocalization();
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState<ThreatHuntingResponse | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const prefersGerman = currentLanguage === 'de' || currentLanguage === 'nl';

  const fallbackCopy: Record<string, string> = prefersGerman
    ? {
        threatHuntTitle: 'Interaktive Threat-Hunting-Abfragen',
        threatHuntDescription: 'Stellen Sie natuerlichsprachige Fragen an die Forensik-Datenbank im Backend. Das Backend uebersetzt sie in schreibgeschuetztes SQL und fasst die Ergebnisse zusammen.',
        threatHuntPrompt: 'Threat-Hunting-Frage',
        threatHuntPlaceholder: 'Zeig mir alle Quell-IPs, die gestern SSH-Verbindungen versucht haben und als brute_force klassifiziert wurden.',
        threatHuntScopedGlobal: 'Die naechste Suche laeuft ueber alle Sensoren.',
        threatHuntRun: 'Suche starten',
        threatHuntRunning: 'Suche laeuft...',
        threatHuntExamplesTitle: 'Beispielabfragen',
        threatHuntExamplesDescription: 'Vorlagen fuer typische Fragen an Traffic, Logs, Sandbox und PCAP-Daten.',
        threatHuntSummary: 'Zusammenfassung',
        threatHuntSql: 'Erzeugtes SQL',
        threatHuntResults: 'Ergebniszeilen',
        threatHuntNoRows: 'Keine Zeilen passen auf diese Abfrage.',
        unknownError: 'Unbekannter Fehler',
      }
    : {
        threatHuntTitle: 'Interactive Threat Hunting',
        threatHuntDescription: 'Ask natural-language questions against the backend forensics database. The backend translates them into read-only SQL and summarizes the result set.',
        threatHuntPrompt: 'Threat hunting question',
        threatHuntPlaceholder: 'Show me all source IPs that attempted SSH connections yesterday and were classified as brute_force.',
        threatHuntScopedGlobal: 'The next hunt runs across all sensors.',
        threatHuntRun: 'Run Hunt',
        threatHuntRunning: 'Running...',
        threatHuntExamplesTitle: 'Example Queries',
        threatHuntExamplesDescription: 'Templates for common questions about traffic, logs, sandbox and PCAP data.',
        threatHuntSummary: 'Summary',
        threatHuntSql: 'Generated SQL',
        threatHuntResults: 'Result Rows',
        threatHuntNoRows: 'No rows matched this query.',
        unknownError: 'Unknown error',
      };

  const resolveText = (key: string, fallback?: string, replacements: { [key: string]: string | number } = {}) => {
    const translated = t(key, replacements);
    let value = translated !== key ? translated : fallback || fallbackCopy[key] || key;
    Object.keys(replacements).forEach(placeholder => {
      const regex = new RegExp(`\\{${placeholder}\\}`, 'g');
      value = value.replace(regex, String(replacements[placeholder]));
    });
    return value;
  };

  const exampleCards = EXAMPLE_DEFINITIONS.map(example => ({
    ...example,
    category: prefersGerman ? example.categoryDe : example.categoryEn,
    text: resolveText(example.key, prefersGerman ? example.fallbackDe : example.fallbackEn),
  }));

  const handleSubmit = async () => {
    if (!question.trim()) {
      return;
    }

    setPending(true);
    setError(null);

    try {
      if (onBeforeRun) {
        await onBeforeRun();
      }
      const response = await runThreatHunt(backendBaseUrl, question.trim(), selectedSensorId);
      setResult(response.result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : resolveText('unknownError'));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white">{resolveText('threatHuntTitle')}</h2>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">{resolveText('threatHuntDescription')}</p>
      </div>

      <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
        <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
          <div className="space-y-3">
            <label className="block text-sm font-medium text-gray-400">{resolveText('threatHuntPrompt')}</label>
            <textarea
              value={question}
              onChange={event => setQuestion(event.target.value)}
              rows={4}
              className="w-full rounded-xl border border-gray-600 bg-gray-900 px-4 py-3 text-white focus:border-blue-500 focus:outline-none"
              placeholder={resolveText('threatHuntPlaceholder')}
            />
            <div className="text-sm text-gray-500">
              {selectedSensorId
                ? resolveText('threatHuntScopedSensor', prefersGerman ? 'Die naechste Suche ist auf den Sensor begrenzt: {sensorName}' : 'The next hunt is scoped to sensor: {sensorName}', {
                    sensorName: sensors.find(sensor => sensor.id === selectedSensorId)?.name || selectedSensorId,
                  })
                : resolveText('threatHuntScopedGlobal')}
            </div>
            <div className="rounded-xl border border-gray-700/70 bg-gray-900/40 p-4">
              <div className="text-sm font-semibold text-gray-200">{resolveText('threatHuntExamplesTitle')}</div>
              <div className="mt-1 text-xs text-gray-500">{resolveText('threatHuntExamplesDescription')}</div>
              <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {exampleCards.map(example => (
                  <button
                    key={example.key}
                    type="button"
                    onClick={() => {
                      setQuestion(example.text);
                      setError(null);
                    }}
                    className="rounded-2xl border border-gray-600 bg-gray-800/70 px-4 py-3 text-left transition hover:border-blue-500 hover:bg-gray-800 hover:text-white"
                  >
                    <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-300">{example.category}</div>
                    <div className="mt-2 text-sm font-medium leading-6 text-gray-100">{example.text}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => void handleSubmit()}
              disabled={pending || !question.trim()}
              className="rounded-xl bg-blue-600 px-5 py-3 font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-700"
            >
              {pending ? resolveText('threatHuntRunning') : resolveText('threatHuntRun')}
            </button>
          </div>
        </div>
        {error && <div className="mt-4 text-sm text-red-300">{error}</div>}
      </section>

      {result && (
        <>
          <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
            <h3 className="text-xl font-semibold text-white">{resolveText('threatHuntSummary')}</h3>
            <p className="mt-3 text-sm leading-6 text-gray-300">{result.summary}</p>
          </section>

          <section className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
            <h3 className="text-xl font-semibold text-white">{resolveText('threatHuntSql')}</h3>
            <pre className="mt-4 overflow-x-auto rounded-xl bg-gray-900 p-4 text-xs text-green-300">{result.sql}</pre>
          </section>

          <section className="overflow-hidden rounded-2xl border border-gray-700/60 bg-[#161B22] shadow-xl">
            <div className="border-b border-gray-700/50 p-4">
              <h3 className="text-xl font-semibold text-white">{resolveText('threatHuntResults')}</h3>
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
                      <td className="p-8 text-center text-gray-500">{resolveText('threatHuntNoRows')}</td>
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
