import crypto from 'node:crypto';
import { executeReadOnlyQuery, getForensicsSchema, insertForensicsQuery } from './db.js';
import { requestProviderJson, Type } from './llmService.js';

const SQL_PLAN_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    sql: { type: Type.STRING },
    reasoning: { type: Type.STRING },
  },
  required: ['sql', 'reasoning'],
};

const SUMMARY_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    summary: { type: Type.STRING },
  },
  required: ['summary'],
};

const SQL_SYSTEM_PROMPT = `You translate security forensics questions into read-only SQLite SQL.
Return strictly valid JSON and nothing else.
Rules:
- Only produce SELECT statements or CTEs that end in a SELECT.
- Never use INSERT, UPDATE, DELETE, DROP, ALTER, ATTACH, DETACH, PRAGMA, VACUUM, or transaction commands.
- Prefer explicit column lists.
- Use SQLite syntax.
- Limit the final result to 200 rows or fewer.
- For sandbox verdict/file questions, use the sandbox_analyses table.
- Do not wrap SQL in markdown fences or commentary.`;

const SUMMARY_SYSTEM_PROMPT = `You summarize security forensics query results.
Return strictly valid JSON and nothing else.
Keep the summary concise and analyst-focused.`;

const SQL_REPAIR_SYSTEM_PROMPT = `You repair a malformed SQL draft into one single safe read-only SQLite query.
Return strictly valid JSON and nothing else.
Rules:
- Return exactly one SELECT statement or one WITH ... SELECT statement.
- Remove markdown fences, labels, commentary and extra statements.
- Never use INSERT, UPDATE, DELETE, DROP, ALTER, ATTACH, DETACH, PRAGMA, VACUUM, transaction commands or CREATE.
- Prefer explicit column lists.
- Limit the final result to 200 rows or fewer.`;

const escapeSqlString = (value) => `'${String(value ?? '').replace(/'/g, "''")}'`;

const normalizeDateExpression = (columnName) => `datetime(replace(replace(${columnName}, 'T', ' '), 'Z', ''))`;

const addSensorCondition = (conditions, sensorId, columnName = 'sensor_id') =>
  sensorId ? [...conditions, `${columnName} = ${escapeSqlString(sensorId)}`] : conditions;

const joinWhere = (conditions) => (conditions.length ? `WHERE ${conditions.join(' AND ')}` : '');

const extractProcessToken = (question) => {
  const explicitFileMatch = question.match(/\b([a-z0-9_.-]+\.(?:exe|dll|bat|cmd|ps1|msi|scr))\b/i);
  if (explicitFileMatch) {
    const raw = explicitFileMatch[1].toLowerCase();
    return {
      raw,
      base: raw.replace(/\.[a-z0-9]+$/i, ''),
    };
  }

  const keywordMatch = question.match(/(?:prozess|process)\s+([a-z0-9_.-]+)/i);
  if (!keywordMatch) {
    return null;
  }

  const raw = keywordMatch[1].toLowerCase();
  return {
    raw,
    base: raw.replace(/\.[a-z0-9]+$/i, ''),
  };
};

const extractPortNumbers = (question) =>
  [...new Set((question.match(/\b\d{1,5}\b/g) || []).map(Number).filter(port => port >= 1 && port <= 65535))];

const buildProcessMatchCondition = (processToken) => {
  if (!processToken) {
    return null;
  }

  const raw = escapeSqlString(processToken.raw);
  const base = escapeSqlString(processToken.base);
  return `(
    lower(coalesce(json_extract(packet_json, '$.localProcess.processName'), '')) = ${raw}
    OR lower(coalesce(json_extract(packet_json, '$.localProcess.processName'), '')) = ${base}
    OR lower(coalesce(json_extract(packet_json, '$.localProcess.displayName'), '')) = ${raw}
    OR lower(coalesce(json_extract(packet_json, '$.localProcess.displayName'), '')) = ${base}
    OR lower(coalesce(json_extract(packet_json, '$.localProcess.executablePath'), '')) LIKE '%' || ${raw} || '%'
    OR lower(coalesce(json_extract(packet_json, '$.localProcess.executablePath'), '')) LIKE '%' || ${base} || '%'
  )`;
};

const normalizeGeneratedSql = sql => {
  let normalized = String(sql ?? '').trim();
  if (!normalized) {
    return '';
  }

  normalized = normalized
    .replace(/^```(?:sql)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .replace(/^sql\s*:\s*/i, '')
    .trim();

  const statementMatch = normalized.match(/\b(select|with)\b/i);
  if (statementMatch) {
    const startIndex = statementMatch.index ?? 0;
    const source = normalized.slice(startIndex);
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inBracketQuote = false;
    let depth = 0;
    let endIndex = source.length;

    for (let index = 0; index < source.length; index += 1) {
      const current = source[index];
      const next = source[index + 1];

      if (inSingleQuote) {
        if (current === '\'' && next === '\'') {
          index += 1;
          continue;
        }
        if (current === '\'') {
          inSingleQuote = false;
        }
        continue;
      }

      if (inDoubleQuote) {
        if (current === '"' && next === '"') {
          index += 1;
          continue;
        }
        if (current === '"') {
          inDoubleQuote = false;
        }
        continue;
      }

      if (inBracketQuote) {
        if (current === ']') {
          inBracketQuote = false;
        }
        continue;
      }

      if (current === '\'') {
        inSingleQuote = true;
        continue;
      }

      if (current === '"') {
        inDoubleQuote = true;
        continue;
      }

      if (current === '[') {
        inBracketQuote = true;
        continue;
      }

      if (current === '(') {
        depth += 1;
        continue;
      }

      if (current === ')' && depth > 0) {
        depth -= 1;
        continue;
      }

      if (current === ';' && depth === 0) {
        endIndex = index;
        break;
      }

      if (depth === 0 && current === '\n') {
        const remainder = source.slice(index).trimStart();
        if (/^(reasoning|explanation|summary|notes?)\s*:/i.test(remainder)) {
          endIndex = index;
          break;
        }
      }
    }

    normalized = source.slice(0, endIndex).trim();
  }

  normalized = normalized.replace(/;+\s*$/g, '').trim();
  return normalized;
};

const isSafeReadOnlySql = (sql) => {
  const normalized = normalizeGeneratedSql(sql).toLowerCase();
  if (!normalized) {
    return false;
  }

  if (!(normalized.startsWith('select') || normalized.startsWith('with'))) {
    return false;
  }

  if (normalized.includes(';')) {
    return false;
  }

  return !/\b(insert|update|delete|drop|alter|attach|detach|pragma|vacuum|begin|commit|rollback|replace|create)\b/i.test(normalized);
};

const ensureLimit = (sql) => {
  if (/\blimit\s+\d+\b/i.test(sql)) {
    return sql;
  }

  return `SELECT * FROM (${sql}) AS threat_hunt_results LIMIT 200`;
};

const buildDeterministicSql = ({ question, sensorId }) => {
  const normalizedQuestion = String(question ?? '').trim().toLowerCase();
  const ports = extractPortNumbers(normalizedQuestion);
  const processToken = extractProcessToken(normalizedQuestion);

  if (/(sandbox).*(suspicious|malicious)|(suspicious|malicious).*(sandbox)/i.test(normalizedQuestion)) {
    return `
      SELECT file_name, verdict, score, provider, status, created_at, sensor_name
      FROM sandbox_analyses
      ${joinWhere(addSensorCondition(["lower(verdict) IN ('suspicious', 'malicious')"], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(last|letzten?)\s+20.*sandbox|sandbox-analysen.*(dateiname|verdict|score)|sandbox analyses.*(file name|verdict|score)/i.test(normalizedQuestion)) {
    return `
      SELECT file_name, verdict, score, provider, status, created_at, sensor_name
      FROM sandbox_analyses
      ${joinWhere(addSensorCondition([], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 20
    `;
  }

  if (/(blocked ip|blockierten ips?)/i.test(normalizedQuestion) && /(24|24 stunden|24 hours|letzten 24|last 24)/i.test(normalizedQuestion)) {
    return `
      SELECT source_ip, COUNT(*) AS block_count, MAX(created_at) AS last_seen_at, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([
        "upper(action_type) = 'BLOCK'",
        `${normalizeDateExpression('created_at')} >= datetime('now', '-1 day')`,
      ], sensorId))}
      GROUP BY source_ip, sensor_name
      ORDER BY block_count DESC, last_seen_at DESC
      LIMIT 200
    `;
  }

  if (processToken && /(verbindungen|connections).*(prozess|process)|(prozess|process).*(verbindungen|connections)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, source_port, destination_port, protocol, attack_type, decision_source, action_type, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([buildProcessMatchCondition(processToken)], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(attacktype|angriffstyp).*(brute_force)|brute_force/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, destination_port, protocol, confidence, decision_source, action_type, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition(["lower(attack_type) = 'brute_force'"], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (ports.length > 0 && /(port 22|port 3389|22 oder 3389|22 or 3389|22|3389)/i.test(normalizedQuestion) && /(quell-ip|source ip|source ips|quell-ips)/i.test(normalizedQuestion)) {
    return `
      SELECT source_ip, destination_port, COUNT(*) AS connection_count, MAX(created_at) AS last_seen_at, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([`destination_port IN (${ports.join(', ')})`], sensorId))}
      GROUP BY source_ip, destination_port, sensor_name
      ORDER BY connection_count DESC, last_seen_at DESC
      LIMIT 200
    `;
  }

  if (/(verdaechtigen verkehr|suspicious traffic)/i.test(normalizedQuestion) && /(2 stunden|2 hours|letzten 2|last 2)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, destination_port, protocol, attack_type, confidence, decision_source, action_type, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([
        'is_suspicious = 1',
        `${normalizeDateExpression('created_at')} >= datetime('now', '-2 hours')`,
      ], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (ports.length > 0 && /(prozess|process).*(5353)|5353.*(prozess|process)/i.test(normalizedQuestion)) {
    return `
      SELECT
        coalesce(
          json_extract(packet_json, '$.localProcess.processName'),
          json_extract(packet_json, '$.localProcess.displayName'),
          json_extract(packet_json, '$.localProcess.executablePath'),
          'unknown'
        ) AS process_name,
        COUNT(*) AS connection_count,
        MAX(created_at) AS last_seen_at,
        sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([`destination_port IN (${ports.join(', ')})`], sensorId))}
      GROUP BY process_name, sensor_name
      ORDER BY connection_count DESC, last_seen_at DESC
      LIMIT 200
    `;
  }

  if (/(decision source|entscheidungsquelle).*(llm)|\bllm\b/i.test(normalizedQuestion) && /(traffic|verkehr|entries|eintraege)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, destination_port, protocol, attack_type, confidence, action_type, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition(["lower(decision_source) = 'llm'"], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(mehr als einmal blockiert|blocked more than once)/i.test(normalizedQuestion)) {
    return `
      SELECT source_ip, COUNT(*) AS block_count, MAX(created_at) AS last_seen_at, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition(["upper(action_type) = 'BLOCK'"], sensorId))}
      GROUP BY source_ip, sensor_name
      HAVING COUNT(*) > 1
      ORDER BY block_count DESC, last_seen_at DESC
      LIMIT 200
    `;
  }

  if (/(fehlgeschlagen|failed).*(cape|cerberus lab|sandbox)|(cape|cerberus lab|sandbox).*(fehlgeschlagen|failed)/i.test(normalizedQuestion)) {
    return `
      SELECT file_name, provider, status, stage, error_message, created_at, sensor_name
      FROM sandbox_analyses
      ${joinWhere(addSensorCondition(["lower(status) = 'failed'"], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(hoechsten sandbox-scores|highest sandbox scores)/i.test(normalizedQuestion) && /(heute|today)/i.test(normalizedQuestion)) {
    return `
      SELECT file_name, verdict, score, provider, created_at, sensor_name
      FROM sandbox_analyses
      ${joinWhere(addSensorCondition([
        `${normalizeDateExpression('created_at')} >= datetime('now', 'start of day')`,
      ], sensorId))}
      ORDER BY score DESC, ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (processToken && /(welche dateien|which files).*(prozess|process)|(prozess|process).*(analysiert|analyzed)/i.test(normalizedQuestion)) {
    return `
      SELECT file_name, verdict, score, provider, status, created_at, sensor_name
      FROM sandbox_analyses
      ${joinWhere(addSensorCondition([
        `(lower(coalesce(process_name, '')) = ${escapeSqlString(processToken.base)} OR lower(coalesce(process_name, '')) = ${escapeSqlString(processToken.raw)})`,
      ], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(kritischen log|critical log)/i.test(normalizedQuestion) && /(heute|today)/i.test(normalizedQuestion)) {
    return `
      SELECT timestamp, level, message, sensor_name
      FROM logs
      ${joinWhere(addSensorCondition([
        "upper(level) = 'CRITICAL'",
        `${normalizeDateExpression('timestamp')} >= datetime('now', 'start of day')`,
      ], sensorId))}
      ORDER BY ${normalizeDateExpression('timestamp')} DESC
      LIMIT 200
    `;
  }

  if (/(pcap-art|pcap art|pcap artifacts|pcap-artefakte)/i.test(normalizedQuestion) && /(other|malicious_payload)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, file_name, attack_type, source_ip, packet_count, bytes, sensor_name
      FROM pcap_artifacts
      ${joinWhere(addSensorCondition(["lower(attack_type) IN ('other', 'malicious_payload')"], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(verdaechtigen udp-verkehr|suspicious udp traffic)/i.test(normalizedQuestion) && /(heute|today)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, source_port, destination_port, attack_type, confidence, decision_source, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([
        "lower(protocol) = 'udp'",
        'is_suspicious = 1',
        `${normalizeDateExpression('created_at')} >= datetime('now', 'start of day')`,
      ], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(ziel-ports|destination ports).*(blockiert|blocked)|(blockiert|blocked).*(ziel-ports|destination ports)/i.test(normalizedQuestion)) {
    return `
      SELECT destination_port, COUNT(*) AS block_count, MAX(created_at) AS last_seen_at, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition(["upper(action_type) = 'BLOCK'"], sensorId))}
      GROUP BY destination_port, sensor_name
      ORDER BY block_count DESC, last_seen_at DESC
      LIMIT 200
    `;
  }

  if (/(windows lab sensor)/i.test(normalizedQuestion) && /(letzten stunde|last hour|letzte stunde)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, destination_port, protocol, attack_type, confidence, decision_source
      FROM traffic_events
      ${joinWhere([
        "sensor_name = 'Windows Lab Sensor'",
        `${normalizeDateExpression('created_at')} >= datetime('now', '-1 hour')`,
      ])}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(decision source|entscheidungsquelle).*(cache)|cache.*(verdaechtigen|suspicious)/i.test(normalizedQuestion)) {
    return `
      SELECT created_at, source_ip, destination_ip, destination_port, protocol, attack_type, confidence, action_type, sensor_name
      FROM traffic_events
      ${joinWhere(addSensorCondition([
        "lower(decision_source) = 'cache'",
        'is_suspicious = 1',
      ], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  if (/(neuesten sandbox-analysen|latest sandbox analyses)/i.test(normalizedQuestion)) {
    return `
      SELECT file_name, verdict, score, status, created_at, sensor_name
      FROM sandbox_analyses
      ${joinWhere(addSensorCondition([], sensorId))}
      ORDER BY ${normalizeDateExpression('created_at')} DESC
      LIMIT 200
    `;
  }

  return null;
};

export class ForensicsChatService {
  async repairUnsafeSql({ question, sensorId, schema, rejectedSql, reasoning, config }) {
    const sensorInstruction = sensorId
      ? `The user is scoped to sensor_id = "${sensorId}". Keep that scope unless the question clearly asks for global data.`
      : 'The user is scoped globally across all sensors unless they ask for one sensor.';

    const repairPrompt = `Schema:\n${JSON.stringify(schema, null, 2)}\n\n${sensorInstruction}\n\nQuestion:\n${question}\n\nMalformed or rejected SQL draft:\n${rejectedSql || '(empty)'}\n\nPlanner reasoning:\n${reasoning || '(none)'}\n\nReturn a repaired safe SQLite query.`;
    const repairedPlan = await requestProviderJson(config, repairPrompt, SQL_PLAN_SCHEMA, {
      systemPrompt: SQL_REPAIR_SYSTEM_PROMPT,
      priority: 'high',
    });
    return normalizeGeneratedSql(typeof repairedPlan?.sql === 'string' ? repairedPlan.sql : '');
  }

  async runQuestion({ question, sensorId, config }) {
    const schema = getForensicsSchema();
    const deterministicSql = buildDeterministicSql({ question, sensorId });
    if (deterministicSql) {
      const limitedSql = ensureLimit(normalizeGeneratedSql(deterministicSql));
      const rows = executeReadOnlyQuery(limitedSql);
      const summaryPrompt = `Question:\n${question}\n\nSQL:\n${limitedSql}\n\nRows:\n${JSON.stringify(rows, null, 2)}`;
      const summaryResponse = await requestProviderJson(config, summaryPrompt, SUMMARY_SCHEMA, {
        systemPrompt: SUMMARY_SYSTEM_PROMPT,
        priority: 'high',
      });

      const result = {
        id: crypto.randomUUID(),
        question,
        sql: limitedSql,
        summary: typeof summaryResponse?.summary === 'string' ? summaryResponse.summary.trim() : 'No summary returned.',
        rows,
        generatedAt: new Date().toISOString(),
        sensorId: sensorId ?? null,
      };

      insertForensicsQuery(result);
      return result;
    }

    const sensorInstruction = sensorId
      ? `The user is currently scoped to sensor_id = "${sensorId}". Prefer filtering to that sensor unless the user clearly asks for global data.`
      : 'The user is asking for a global view across all sensors unless they request otherwise.';

    const planningPrompt = `Schema:\n${JSON.stringify(schema, null, 2)}\n\n${sensorInstruction}\n\nQuestion:\n${question}`;
    const plannedQuery = await requestProviderJson(config, planningPrompt, SQL_PLAN_SCHEMA, {
      systemPrompt: SQL_SYSTEM_PROMPT,
      priority: 'high',
    });

    let sql = normalizeGeneratedSql(typeof plannedQuery?.sql === 'string' ? plannedQuery.sql : '');
    if (!isSafeReadOnlySql(sql)) {
      sql = await this.repairUnsafeSql({
        question,
        sensorId,
        schema,
        rejectedSql: typeof plannedQuery?.sql === 'string' ? plannedQuery.sql : '',
        reasoning: typeof plannedQuery?.reasoning === 'string' ? plannedQuery.reasoning : '',
        config,
      });
    }

    if (!isSafeReadOnlySql(sql)) {
      throw new Error('The generated SQL query was rejected by the read-only safety policy.');
    }

    const limitedSql = ensureLimit(sql);
    const rows = executeReadOnlyQuery(limitedSql);

    const summaryPrompt = `Question:\n${question}\n\nSQL:\n${limitedSql}\n\nRows:\n${JSON.stringify(rows, null, 2)}`;
    const summaryResponse = await requestProviderJson(config, summaryPrompt, SUMMARY_SCHEMA, {
      systemPrompt: SUMMARY_SYSTEM_PROMPT,
      priority: 'high',
    });

    const result = {
      id: crypto.randomUUID(),
      question,
      sql: limitedSql,
      summary: typeof summaryResponse?.summary === 'string' ? summaryResponse.summary.trim() : 'No summary returned.',
      rows,
      generatedAt: new Date().toISOString(),
      sensorId: sensorId ?? null,
    };

    insertForensicsQuery(result);
    return result;
  }
}
