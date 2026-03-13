import React from 'react';
import { ActionType, AttackType, Configuration, CustomRule, CustomRuleCondition } from '../types';
import { useLocalization } from '../hooks/useLocalization';
import { createId } from '../utils';

interface RuleBuilderProps {
  config: Configuration;
  setConfig: React.Dispatch<React.SetStateAction<Configuration>>;
  configSyncState: 'idle' | 'saving' | 'saved' | 'error';
}

const FIELD_OPTIONS: CustomRuleCondition['field'][] = [
  'sourceIp',
  'destinationIp',
  'sourcePort',
  'destinationPort',
  'protocol',
  'direction',
  'size',
  'l7Protocol',
  'payloadSnippet',
  'l7.host',
  'l7.path',
  'l7.userAgent',
  'l7.dnsQuery',
  'l7.sni',
  'l7.sshBanner',
  'l7.ftpCommand',
  'l7.rdpCookie',
  'l7.smbCommand',
  'l7.sqlOperation',
];

const OPERATOR_OPTIONS: CustomRuleCondition['operator'][] = [
  'equals',
  'not_equals',
  'greater_than',
  'less_than',
  'contains',
  'starts_with',
  'in_cidr',
  'not_in_cidr',
  'in_list',
  'not_in_list',
];

const createDefaultCondition = (): CustomRuleCondition => ({
  id: createId(),
  field: 'destinationPort',
  operator: 'equals',
  value: '3389',
});

const createDefaultRule = (name: string, explanation: string): CustomRule => ({
  id: createId(),
  name,
  enabled: true,
  matchMode: 'all',
  conditions: [createDefaultCondition()],
  outcome: {
    actionType: ActionType.BLOCK,
    attackType: AttackType.OTHER,
    confidence: 0.9,
    explanation,
    needsDeepInspection: false,
  },
});

const InputLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-gray-400">{children}</label>
);

const SyncBadge: React.FC<{ state: RuleBuilderProps['configSyncState']; label: string }> = ({ state, label }) => {
  const colorClass =
    state === 'saving'
      ? 'border-yellow-500/30 bg-yellow-500/15 text-yellow-100'
      : state === 'saved'
        ? 'border-emerald-500/30 bg-emerald-500/15 text-emerald-100'
        : state === 'error'
          ? 'border-red-500/30 bg-red-500/15 text-red-100'
          : 'border-gray-600/50 bg-gray-700/50 text-gray-300';

  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${colorClass}`}>
      {label}
    </span>
  );
};

export const RuleBuilder: React.FC<RuleBuilderProps> = ({ config, setConfig, configSyncState }) => {
  const { t } = useLocalization();

  const updateRule = (ruleId: string, updater: (rule: CustomRule) => CustomRule) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      customRules: previousConfig.customRules.map(rule => (rule.id === ruleId ? updater(rule) : rule)),
    }));
  };

  const addRule = () => {
    setConfig(previousConfig => ({
      ...previousConfig,
      customRules: [...previousConfig.customRules, createDefaultRule(t('newCustomRuleName'), t('newCustomRuleExplanation'))],
    }));
  };

  const removeRule = (ruleId: string) => {
    setConfig(previousConfig => ({
      ...previousConfig,
      customRules: previousConfig.customRules.filter(rule => rule.id !== ruleId),
    }));
  };

  const addCondition = (ruleId: string) => {
    updateRule(ruleId, rule => ({
      ...rule,
      conditions: [...rule.conditions, createDefaultCondition()],
    }));
  };

  const updateCondition = (ruleId: string, conditionId: string, patch: Partial<CustomRuleCondition>) => {
    updateRule(ruleId, rule => ({
      ...rule,
      conditions: rule.conditions.map(condition =>
        condition.id === conditionId
          ? {
              ...condition,
              ...patch,
            }
          : condition
      ),
    }));
  };

  const removeCondition = (ruleId: string, conditionId: string) => {
    updateRule(ruleId, rule => ({
      ...rule,
      conditions: rule.conditions.filter(condition => condition.id !== conditionId),
    }));
  };

  const syncStateLabel =
    configSyncState === 'saving'
      ? t('configSyncSaving')
      : configSyncState === 'saved'
        ? t('configSyncSaved')
        : configSyncState === 'error'
          ? t('configSyncError')
          : t('configSyncIdle');

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white">{t('rulesTitle')}</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">{t('rulesDescription')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <SyncBadge state={configSyncState} label={syncStateLabel} />
          <button
            onClick={addRule}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
          >
            {t('addRule')}
          </button>
        </div>
      </div>

      {config.customRules.length === 0 && (
        <div className="rounded-2xl border border-dashed border-gray-700 bg-[#161B22] p-10 text-center text-sm text-gray-500">
          {t('rulesEmptyState')}
        </div>
      )}

      {config.customRules.map(rule => (
        <section key={rule.id} className="rounded-2xl border border-gray-700/60 bg-[#161B22] p-6 shadow-xl">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="grid flex-1 grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <InputLabel>{t('ruleName')}</InputLabel>
                <input
                  type="text"
                  value={rule.name}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, name: event.target.value }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div>
                <InputLabel>{t('ruleMatchMode')}</InputLabel>
                <select
                  value={rule.matchMode}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, matchMode: event.target.value as CustomRule['matchMode'] }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="all">{t('ruleMatchModeAll')}</option>
                  <option value="any">{t('ruleMatchModeAny')}</option>
                </select>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <label className="flex items-center gap-3 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, enabled: event.target.checked }))}
                  className="h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500"
                />
                {t('ruleEnabled')}
              </label>
              <button
                onClick={() => removeRule(rule.id)}
                className="rounded-lg border border-red-500/40 px-3 py-2 text-sm font-semibold text-red-300 transition hover:bg-red-500/10"
              >
                {t('removeRule')}
              </button>
            </div>
          </div>

          <div className="mt-6 rounded-2xl border border-gray-700/60 bg-gray-900/40 p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white">{t('ruleConditions')}</h3>
                <p className="mt-1 text-sm text-gray-400">{t('ruleConditionsHint')}</p>
              </div>
              <button
                onClick={() => addCondition(rule.id)}
                className="rounded-lg bg-gray-700 px-3 py-2 text-sm font-semibold text-white transition hover:bg-gray-600"
              >
                {t('addCondition')}
              </button>
            </div>

            <div className="space-y-4">
              {rule.conditions.map(condition => (
                <div key={condition.id} className="grid gap-4 rounded-xl border border-gray-700 bg-[#11161d] p-4 lg:grid-cols-[1.2fr_1fr_1.2fr_auto]">
                  <div>
                    <InputLabel>{t('ruleField')}</InputLabel>
                    <select
                      value={condition.field}
                      onChange={event => updateCondition(rule.id, condition.id, { field: event.target.value as CustomRuleCondition['field'] })}
                      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                    >
                      {FIELD_OPTIONS.map(field => (
                        <option key={field} value={field}>{t(`ruleField_${field}`)}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <InputLabel>{t('ruleOperator')}</InputLabel>
                    <select
                      value={condition.operator}
                      onChange={event => updateCondition(rule.id, condition.id, { operator: event.target.value as CustomRuleCondition['operator'] })}
                      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                    >
                      {OPERATOR_OPTIONS.map(operator => (
                        <option key={operator} value={operator}>{t(`ruleOperator_${operator}`)}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <InputLabel>{t('ruleValue')}</InputLabel>
                    <input
                      type="text"
                      value={condition.value}
                      onChange={event => updateCondition(rule.id, condition.id, { value: event.target.value })}
                      className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                    />
                  </div>

                  <div className="flex items-end">
                    <button
                      onClick={() => removeCondition(rule.id, condition.id)}
                      disabled={rule.conditions.length === 1}
                      className="w-full rounded-lg border border-gray-600 px-3 py-2 text-sm font-semibold text-gray-300 transition hover:border-red-500 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {t('remove')}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-6 rounded-2xl border border-gray-700/60 bg-gray-900/40 p-5">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-white">{t('ruleOutcome')}</h3>
              <p className="mt-1 text-sm text-gray-400">{t('ruleOutcomeHint')}</p>
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div>
                <InputLabel>{t('ruleAction')}</InputLabel>
                <select
                  value={rule.outcome.actionType}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, actionType: event.target.value as ActionType } }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value={ActionType.ALLOW}>{t('ruleAction_allow')}</option>
                  <option value={ActionType.BLOCK}>{t('ruleAction_block')}</option>
                  <option value={ActionType.REDIRECT}>{t('ruleAction_redirect')}</option>
                </select>
              </div>

              <div>
                <InputLabel>{t('ruleAttackType')}</InputLabel>
                <select
                  value={rule.outcome.attackType}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, attackType: event.target.value as AttackType } }))}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                >
                  {Object.values(AttackType).map(attackType => (
                    <option key={attackType} value={attackType}>{t(`attackType_${attackType}`)}</option>
                  ))}
                </select>
              </div>

              <div>
                <InputLabel>{t('ruleConfidence')}</InputLabel>
                <div className="rounded-lg border border-gray-600 bg-gray-900 px-3 py-2">
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    value={rule.outcome.confidence}
                    onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, confidence: Number.parseFloat(event.target.value) } }))}
                    className="w-full"
                  />
                  <div className="mt-2 text-sm font-semibold text-blue-300">{(rule.outcome.confidence * 100).toFixed(0)}%</div>
                </div>
              </div>

              <div>
                <InputLabel>{t('ruleRedirectPort')}</InputLabel>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={rule.outcome.targetPort ?? ''}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, targetPort: event.target.value ? Number.parseInt(event.target.value, 10) : undefined } }))}
                  disabled={rule.outcome.actionType !== ActionType.REDIRECT}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none disabled:cursor-not-allowed disabled:opacity-40"
                />
              </div>
            </div>

            <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_auto]">
              <div>
                <InputLabel>{t('ruleExplanation')}</InputLabel>
                <textarea
                  value={rule.outcome.explanation}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, explanation: event.target.value } }))}
                  rows={3}
                  className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                />
              </div>

              <label className="flex items-center gap-3 rounded-xl border border-gray-700 bg-[#11161d] px-4 py-3 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={rule.outcome.needsDeepInspection}
                  onChange={event => updateRule(rule.id, currentRule => ({ ...currentRule, outcome: { ...currentRule.outcome, needsDeepInspection: event.target.checked } }))}
                  className="h-4 w-4 rounded border-gray-500 bg-gray-900 text-blue-600 focus:ring-blue-500"
                />
                {t('ruleNeedsDeepInspection')}
              </label>
            </div>
          </div>
        </section>
      ))}
    </div>
  );
};
