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
- Limit the final result to 200 rows or fewer.`;

const SUMMARY_SYSTEM_PROMPT = `You summarize security forensics query results.
Return strictly valid JSON and nothing else.
Keep the summary concise and analyst-focused.`;

const isSafeReadOnlySql = (sql) => {
  const normalized = sql.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (!(normalized.startsWith('select') || normalized.startsWith('with'))) {
    return false;
  }

  if (normalized.includes(';')) {
    return false;
  }

  return !/\b(insert|update|delete|drop|alter|attach|detach|pragma|vacuum|begin|commit|rollback|replace|create)\b/i.test(sql);
};

const ensureLimit = (sql) => {
  if (/\blimit\s+\d+\b/i.test(sql)) {
    return sql;
  }

  return `SELECT * FROM (${sql}) AS threat_hunt_results LIMIT 200`;
};

export class ForensicsChatService {
  async runQuestion({ question, sensorId, config }) {
    const schema = getForensicsSchema();
    const sensorInstruction = sensorId
      ? `The user is currently scoped to sensor_id = "${sensorId}". Prefer filtering to that sensor unless the user clearly asks for global data.`
      : 'The user is asking for a global view across all sensors unless they request otherwise.';

    const planningPrompt = `Schema:\n${JSON.stringify(schema, null, 2)}\n\n${sensorInstruction}\n\nQuestion:\n${question}`;
    const plannedQuery = await requestProviderJson(config, planningPrompt, SQL_PLAN_SCHEMA, {
      systemPrompt: SQL_SYSTEM_PROMPT,
      priority: 'high',
    });

    const sql = typeof plannedQuery?.sql === 'string' ? plannedQuery.sql.trim() : '';
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
