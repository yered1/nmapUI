import React, { useCallback } from 'react';
import type { FilterGroup, FilterRule, FilterOperator } from '../types/nmap';
import { FILTER_FIELDS, FILTER_OPERATORS } from '../utils/filterEngine';

interface FilterPanelProps {
  filterGroup: FilterGroup;
  onChange: (group: FilterGroup) => void;
  onClose: () => void;
}

function newRuleId(): string {
  return `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function FilterPanel({ filterGroup, onChange, onClose }: FilterPanelProps) {
  const addRule = useCallback(() => {
    const newRule: FilterRule = {
      id: newRuleId(),
      field: 'ip',
      operator: 'contains',
      value: '',
      enabled: true,
    };
    onChange({
      ...filterGroup,
      rules: [...filterGroup.rules, newRule],
    });
  }, [filterGroup, onChange]);

  const updateRule = useCallback((id: string, updates: Partial<FilterRule>) => {
    onChange({
      ...filterGroup,
      rules: filterGroup.rules.map(r => r.id === id ? { ...r, ...updates } : r),
    });
  }, [filterGroup, onChange]);

  const removeRule = useCallback((id: string) => {
    onChange({
      ...filterGroup,
      rules: filterGroup.rules.filter(r => r.id !== id),
    });
  }, [filterGroup, onChange]);

  const toggleLogic = useCallback(() => {
    onChange({
      ...filterGroup,
      logic: filterGroup.logic === 'AND' ? 'OR' : 'AND',
    });
  }, [filterGroup, onChange]);

  const clearAll = useCallback(() => {
    onChange({ ...filterGroup, rules: [] });
  }, [filterGroup, onChange]);

  const getOperatorsForField = (fieldName: string) => {
    const field = FILTER_FIELDS.find(f => f.value === fieldName);
    const fieldType = field?.type || 'string';
    return FILTER_OPERATORS.filter(op => op.types.includes(fieldType));
  };

  return (
    <div className="filter-panel" role="region" aria-label="Filter panel">
      <div className="filter-header">
        <div className="filter-header-title">
          Filters
          {filterGroup.rules.length > 0 && (
            <span style={{ marginLeft: 8 }}>
              <button
                className="btn btn-sm btn-ghost"
                onClick={toggleLogic}
                title="Toggle between AND/OR logic"
                aria-label={`Match logic: ${filterGroup.logic}. Click to toggle.`}
              >
                Match: {filterGroup.logic}
              </button>
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {filterGroup.rules.length > 0 && (
            <button className="btn btn-sm btn-ghost btn-danger" onClick={clearAll} aria-label="Clear all filters">
              Clear All
            </button>
          )}
          <button className="btn btn-sm btn-primary" onClick={addRule} aria-label="Add a new filter rule">
            + Add Filter
          </button>
          <button className="btn btn-sm btn-ghost" onClick={onClose} aria-label="Close filter panel">
            Close
          </button>
        </div>
      </div>

      {filterGroup.rules.map((rule, idx) => (
        <div key={rule.id} className="filter-row">
          {idx > 0 && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 30, textAlign: 'center', flexShrink: 0 }}>
              {filterGroup.logic}
            </span>
          )}
          <label className="checkbox-label" style={{ flexShrink: 0 }}>
            <input
              type="checkbox"
              checked={rule.enabled}
              onChange={e => updateRule(rule.id, { enabled: e.target.checked })}
              aria-label={`Enable filter rule ${idx + 1}`}
            />
          </label>
          <select
            className="select"
            value={rule.field}
            aria-label={`Filter field for rule ${idx + 1}`}
            onChange={e => {
              const newField = e.target.value;
              const ops = getOperatorsForField(newField);
              const currentOpValid = ops.find(o => o.value === rule.operator);
              updateRule(rule.id, {
                field: newField,
                operator: currentOpValid ? rule.operator : ops[0]?.value as FilterOperator,
              });
            }}
          >
            {FILTER_FIELDS.map(f => (
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
          <select
            className="select"
            value={rule.operator}
            aria-label={`Filter operator for rule ${idx + 1}`}
            onChange={e => updateRule(rule.id, { operator: e.target.value as FilterOperator })}
          >
            {getOperatorsForField(rule.field).map(op => (
              <option key={op.value} value={op.value}>{op.label}</option>
            ))}
          </select>
          {rule.operator !== 'is_empty' && rule.operator !== 'is_not_empty' && (
            <input
              className="input"
              type="text"
              value={rule.value}
              placeholder={rule.operator === 'in_range' ? 'e.g. 1-1024' : 'Value...'}
              onChange={e => updateRule(rule.id, { value: e.target.value })}
              aria-label={`Filter value for rule ${idx + 1}`}
            />
          )}
          <button
            className="btn btn-sm btn-icon btn-ghost btn-danger"
            onClick={() => removeRule(rule.id)}
            title="Remove filter"
            aria-label={`Remove filter rule ${idx + 1}`}
          >
            X
          </button>
        </div>
      ))}

      {filterGroup.rules.length === 0 && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '4px 0' }}>
          No filters applied. Click &quot;+ Add Filter&quot; to add one.
        </div>
      )}
    </div>
  );
}
