import React, { useState, useMemo, useCallback } from 'react';
import type { NmapHost, Port, ScriptSuggestion } from '../types/nmap';
import { getScriptSuggestions, generateNmapCommand } from '../utils/scriptSuggestions';
import { copyToClipboard } from '../utils/helpers';

interface ScriptSuggestionsProps {
  host: NmapHost;
  onImportResults?: () => void;
}

interface PortSuggestion {
  port: Port;
  suggestions: ScriptSuggestion[];
  alreadyRan: Set<string>;
}

export function ScriptSuggestions({ host, onImportResults }: ScriptSuggestionsProps) {
  const [selectedScripts, setSelectedScripts] = useState<Map<string, Set<string>>>(new Map());
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [copiedPort, setCopiedPort] = useState<string | null>(null);

  const portSuggestions = useMemo((): PortSuggestion[] => {
    return host.ports
      .filter(p => p.state.state === 'open' || p.state.state === 'open|filtered')
      .map(port => {
        const suggestions = getScriptSuggestions(port.portid, port.service?.name);
        const alreadyRan = new Set(port.scripts.map(s => s.id));
        return { port, suggestions, alreadyRan };
      })
      .filter(ps => ps.suggestions.length > 0);
  }, [host.ports]);

  const allCategories = useMemo(() => {
    const cats = new Set<string>();
    for (const ps of portSuggestions) {
      for (const s of ps.suggestions) {
        cats.add(s.category);
      }
    }
    return Array.from(cats).sort();
  }, [portSuggestions]);

  const toggleScript = useCallback((portKey: string, scriptId: string) => {
    setSelectedScripts(prev => {
      const next = new Map(prev);
      const portSet = new Set(next.get(portKey) || []);
      if (portSet.has(scriptId)) {
        portSet.delete(scriptId);
      } else {
        portSet.add(scriptId);
      }
      if (portSet.size === 0) {
        next.delete(portKey);
      } else {
        next.set(portKey, portSet);
      }
      return next;
    });
  }, []);

  const selectAllForPort = useCallback((portKey: string, scripts: ScriptSuggestion[], alreadyRan: Set<string>) => {
    setSelectedScripts(prev => {
      const next = new Map(prev);
      const newScripts = scripts.filter(s => !alreadyRan.has(s.scriptId));
      next.set(portKey, new Set(newScripts.map(s => s.scriptId)));
      return next;
    });
  }, []);

  const copyCommand = useCallback(async (portKey: string, port: Port) => {
    const scripts = selectedScripts.get(portKey);
    if (!scripts || scripts.size === 0) return;

    const ip = host.ip || host.ipv6;
    const cmd = generateNmapCommand(ip, port.portid, port.protocol, Array.from(scripts));
    await copyToClipboard(cmd);
    setCopiedPort(portKey);
    setTimeout(() => setCopiedPort(null), 2000);
  }, [selectedScripts, host]);

  const copyAllCommands = useCallback(async () => {
    const commands: string[] = [];
    for (const [portKey, scripts] of selectedScripts) {
      if (scripts.size === 0) continue;
      const ps = portSuggestions.find(p => `${p.port.portid}/${p.port.protocol}` === portKey);
      if (!ps) continue;
      const ip = host.ip || host.ipv6;
      commands.push(generateNmapCommand(ip, ps.port.portid, ps.port.protocol, Array.from(scripts)));
    }
    if (commands.length > 0) {
      await copyToClipboard(commands.join('\n'));
    }
  }, [selectedScripts, portSuggestions, host]);

  const totalSelected = useMemo(() => {
    let count = 0;
    for (const scripts of selectedScripts.values()) {
      count += scripts.size;
    }
    return count;
  }, [selectedScripts]);

  const getCategoryColor = (cat: string): string => {
    switch (cat) {
      case 'vuln': return 'var(--red)';
      case 'brute': return 'var(--orange)';
      case 'auth': return 'var(--yellow)';
      case 'discovery': return 'var(--accent)';
      default: return 'var(--text-secondary)';
    }
  };

  if (portSuggestions.length === 0) {
    return (
      <div className="empty-state">
        <div className="icon">{'\u2699'}</div>
        <div>No script suggestions available for this host's open ports</div>
      </div>
    );
  }

  return (
    <div>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <select
          className="select"
          value={categoryFilter}
          onChange={e => setCategoryFilter(e.target.value)}
        >
          <option value="all">All Categories</option>
          {allCategories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <div className="header-spacer" />
        {totalSelected > 0 && (
          <>
            <span className="result-count">{totalSelected} script{totalSelected !== 1 ? 's' : ''} selected</span>
            <button className="btn btn-sm" onClick={copyAllCommands}>
              Copy All Commands
            </button>
          </>
        )}
        {onImportResults && (
          <button className="btn btn-sm btn-primary" onClick={onImportResults}>
            Import Results
          </button>
        )}
      </div>

      {/* Per-port suggestions */}
      {portSuggestions.map(({ port, suggestions, alreadyRan }) => {
        const portKey = `${port.portid}/${port.protocol}`;
        const portSelected = selectedScripts.get(portKey) || new Set();
        const filteredSuggestions = categoryFilter === 'all'
          ? suggestions
          : suggestions.filter(s => s.category === categoryFilter);

        if (filteredSuggestions.length === 0) return null;

        const newSuggestions = filteredSuggestions.filter(s => !alreadyRan.has(s.scriptId));
        const ranSuggestions = filteredSuggestions.filter(s => alreadyRan.has(s.scriptId));

        return (
          <div key={portKey} className="card" style={{ marginBottom: 12 }}>
            <div className="card-header">
              <span className="mono" style={{ color: 'var(--accent)' }}>
                {port.portid}/{port.protocol}
              </span>
              <span style={{ color: 'var(--text-secondary)', fontWeight: 400, fontSize: 12 }}>
                {port.service?.name || ''}
                {port.service?.product ? ` - ${port.service.product}` : ''}
              </span>
              <div className="header-spacer" />
              {newSuggestions.length > 0 && (
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={() => selectAllForPort(portKey, filteredSuggestions, alreadyRan)}
                  style={{ fontSize: 10 }}
                >
                  Select All New
                </button>
              )}
              {portSelected.size > 0 && (
                <button
                  className="btn btn-sm"
                  onClick={() => copyCommand(portKey, port)}
                  style={{ fontSize: 10 }}
                >
                  {copiedPort === portKey ? 'Copied!' : 'Copy Command'}
                </button>
              )}
            </div>
            <div className="card-body" style={{ padding: '8px 16px' }}>
              {newSuggestions.length > 0 && (
                <div>
                  {newSuggestions.map(s => (
                    <label key={s.scriptId} className="script-suggestion-row">
                      <input
                        type="checkbox"
                        checked={portSelected.has(s.scriptId)}
                        onChange={() => toggleScript(portKey, s.scriptId)}
                        style={{ accentColor: 'var(--accent)' }}
                      />
                      <code className="script-suggestion-id">{s.scriptId}</code>
                      <span
                        className="script-suggestion-cat"
                        style={{ color: getCategoryColor(s.category) }}
                      >
                        {s.category}
                      </span>
                      <span className="script-suggestion-desc">{s.description}</span>
                    </label>
                  ))}
                </div>
              )}
              {ranSuggestions.length > 0 && (
                <div style={{ marginTop: newSuggestions.length > 0 ? 8 : 0 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Already executed
                  </div>
                  {ranSuggestions.map(s => (
                    <div key={s.scriptId} className="script-suggestion-row script-suggestion-done">
                      <span style={{ width: 16 }}>{'\u2713'}</span>
                      <code className="script-suggestion-id">{s.scriptId}</code>
                      <span
                        className="script-suggestion-cat"
                        style={{ color: getCategoryColor(s.category) }}
                      >
                        {s.category}
                      </span>
                      <span className="script-suggestion-desc">{s.description}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
