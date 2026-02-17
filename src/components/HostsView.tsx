import React, { useState, useCallback } from 'react';
import type { NmapScan, NmapHost, SortConfig, FilterRule } from '../types/nmap';
import type { AppStore } from '../store/appStore';
import { FilterPanel } from './FilterPanel';
import { HostDetail } from './HostDetail';
import { ContextMenu, ContextMenuItem } from './ContextMenu';
import { stateClass, copyToClipboard } from '../utils/helpers';

interface HostsViewProps {
  scan: NmapScan;
  hosts: NmapHost[];
  store: AppStore;
  onImportResults?: () => void;
}

const ALL_COLUMNS = [
  { field: 'ip', label: 'IP Address', default: true },
  { field: 'ipv6', label: 'IPv6', default: false },
  { field: 'hostname', label: 'Hostname', default: true },
  { field: 'status', label: 'Status', default: true },
  { field: 'openPortCount', label: 'Open', default: true },
  { field: 'closedPortCount', label: 'Closed', default: true },
  { field: 'filteredPortCount', label: 'Filtered', default: true },
  { field: 'mainOS', label: 'OS', default: true },
  { field: 'mac', label: 'MAC', default: true },
  { field: 'allHostnames', label: 'All Hostnames', default: false },
];

function getHostField(host: NmapHost, field: string): string {
  switch (field) {
    case 'ip': return host.ip || host.ipv6 || 'N/A';
    case 'ipv6': return host.ipv6 || '-';
    case 'hostname': return host.hostname || '-';
    case 'allHostnames': return host.hostnames.map(h => h.name).join(', ') || '-';
    case 'status': return host.status.state;
    case 'openPortCount': return String(host.openPortCount);
    case 'closedPortCount': return String(host.closedPortCount);
    case 'filteredPortCount': return String(host.filteredPortCount);
    case 'mainOS': return host.mainOS || '-';
    case 'mac': return host.mac || '-';
    default: return '-';
  }
}

export function HostsView({ scan, hosts, store, onImportResults }: HostsViewProps) {
  const { state, selectedHost } = store;
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(
    new Set(ALL_COLUMNS.filter(c => c.default).map(c => c.field))
  );
  const [showColumnPicker, setShowColumnPicker] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; host: NmapHost } | null>(null);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 200;

  const columns = ALL_COLUMNS.filter(c => visibleColumns.has(c.field));
  const pagedHosts = hosts.slice(0, (page + 1) * PAGE_SIZE);
  const hasMore = pagedHosts.length < hosts.length;

  const getSortIndicator = (field: string) => {
    const sort = state.sorts.find((s: SortConfig) => s.field === field);
    if (!sort) return '';
    return sort.direction === 'asc' ? ' \u25B2' : ' \u25BC';
  };

  const handleContextMenu = useCallback((e: React.MouseEvent, host: NmapHost) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, host });
  }, []);

  const getContextMenuItems = (host: NmapHost): ContextMenuItem[] => [
    { label: 'View Details', action: () => store.setSelectedHostId(host.id) },
    { label: 'Copy IP', action: () => copyToClipboard(host.ip || host.ipv6) },
    { label: 'Copy Hostname', action: () => copyToClipboard(host.hostname), disabled: !host.hostname },
    { label: 'Copy MAC', action: () => copyToClipboard(host.mac), disabled: !host.mac },
    { label: '', action: () => {}, separator: true },
    {
      label: 'Copy Open Ports',
      action: () => copyToClipboard(host.ports.filter(p => p.state.state === 'open').map(p => `${p.portid}/${p.protocol}`).join(', ')),
      disabled: host.openPortCount === 0,
    },
    {
      label: 'Copy All Port Info',
      action: () => {
        const lines = host.ports.map(p =>
          `${p.portid}/${p.protocol}\t${p.state.state}\t${p.service?.name || ''}\t${p.service?.product || ''}\t${p.service?.version || ''}`
        );
        copyToClipboard(['Port\tState\tService\tProduct\tVersion', ...lines].join('\n'));
      },
    },
    { label: '', action: () => {}, separator: true },
    {
      label: state.selectedHostIds.has(host.id) ? 'Deselect' : 'Select',
      action: () => store.toggleHostSelection(host.id),
    },
    {
      label: 'Copy Selected IPs',
      action: () => {
        const ips = hosts.filter(h => state.selectedHostIds.has(h.id)).map(h => h.ip || h.ipv6).join('\n');
        copyToClipboard(ips);
      },
      disabled: state.selectedHostIds.size === 0,
    },
  ];

  if (selectedHost) {
    return (
      <HostDetail
        host={selectedHost}
        onBack={() => store.setSelectedHostId(null)}
        store={store}
        onImportResults={onImportResults}
      />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Toolbar */}
      <div className="toolbar" role="toolbar" aria-label="Host table controls">
        <div className="search-box">
          <span className="icon" aria-hidden="true">{'\u2315'}</span>
          <input
            className="input"
            type="search"
            placeholder="Search hosts (IP, hostname, service, OS...) - Ctrl+F"
            value={state.searchQuery}
            onChange={e => store.setSearchQuery(e.target.value)}
            style={{ paddingLeft: 28 }}
            aria-label="Search hosts"
          />
        </div>
        <button
          className={`btn btn-sm ${state.showFilterPanel ? 'btn-primary' : ''}`}
          onClick={() => store.setShowFilterPanel(!state.showFilterPanel)}
          aria-expanded={state.showFilterPanel}
          aria-label="Toggle filter panel"
        >
          Filters {state.filterGroup.rules.filter((r: FilterRule) => r.enabled).length > 0 &&
            `(${state.filterGroup.rules.filter((r: FilterRule) => r.enabled).length})`}
        </button>
        <div style={{ position: 'relative' }}>
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => setShowColumnPicker(!showColumnPicker)}
            aria-label="Configure visible columns"
          >
            Columns
          </button>
          {showColumnPicker && (
            <div style={{
              position: 'absolute',
              top: '100%',
              right: 0,
              zIndex: 100,
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: 8,
              boxShadow: 'var(--shadow-lg)',
              minWidth: 160,
            }}>
              {ALL_COLUMNS.map(col => (
                <label key={col.field + col.label} className="checkbox-label" style={{ padding: '3px 0' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns.has(col.field)}
                    onChange={e => {
                      const next = new Set(visibleColumns);
                      if (e.target.checked) next.add(col.field);
                      else next.delete(col.field);
                      setVisibleColumns(next);
                    }}
                  />
                  {col.label}
                </label>
              ))}
            </div>
          )}
        </div>
        <div className="toolbar-divider" />
        <span className="result-count" aria-live="polite">
          {hosts.length} of {scan.hosts.length} hosts
        </span>
        <div className="header-spacer" />
        {state.selectedHostIds.size > 0 ? (
          <>
            <span className="result-count">{state.selectedHostIds.size} selected</span>
            <button className="btn btn-sm btn-ghost" onClick={() => {
              const ips = hosts.filter(h => state.selectedHostIds.has(h.id)).map(h => h.ip || h.ipv6).join('\n');
              copyToClipboard(ips);
            }} aria-label="Copy selected IPs">
              Copy IPs
            </button>
            <button className="btn btn-sm btn-ghost" onClick={store.clearSelection} aria-label="Clear selection">
              Clear
            </button>
          </>
        ) : (
          <button className="btn btn-sm btn-ghost" onClick={() => store.selectAllHosts(hosts)} aria-label="Select all hosts">
            Select All
          </button>
        )}
      </div>

      {/* Filter Panel */}
      {state.showFilterPanel && (
        <FilterPanel
          filterGroup={state.filterGroup}
          onChange={store.setFilterGroup}
          onClose={() => store.setShowFilterPanel(false)}
        />
      )}

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }} role="region" aria-label="Hosts table">
        <table className="data-table" role="grid" aria-label="Hosts">
          <thead>
            <tr>
              <th style={{ width: 32 }} role="columnheader">
                <input
                  type="checkbox"
                  checked={hosts.length > 0 && state.selectedHostIds.size === hosts.length}
                  onChange={e => e.target.checked ? store.selectAllHosts(hosts) : store.clearSelection()}
                  style={{ accentColor: 'var(--accent)' }}
                  aria-label="Select all hosts"
                />
              </th>
              <th style={{ width: 24, cursor: 'default' }} role="columnheader" title="Notes"></th>
              {columns.map(col => (
                <th
                  key={col.field}
                  onClick={() => store.toggleSort(col.field)}
                  role="columnheader"
                  aria-sort={
                    state.sorts.find((s: SortConfig) => s.field === col.field)
                      ? state.sorts.find((s: SortConfig) => s.field === col.field)!.direction === 'asc' ? 'ascending' : 'descending'
                      : 'none'
                  }
                  tabIndex={0}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') store.toggleSort(col.field); }}
                >
                  {col.label}
                  <span className="sort-indicator" aria-hidden="true">{getSortIndicator(col.field)}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pagedHosts.map(host => (
              <tr
                key={host.id}
                className={`clickable ${state.selectedHostIds.has(host.id) ? 'selected' : ''}`}
                onClick={() => store.setSelectedHostId(host.id)}
                onContextMenu={e => handleContextMenu(e, host)}
                tabIndex={0}
                onKeyDown={e => { if (e.key === 'Enter') store.setSelectedHostId(host.id); }}
                role="row"
              >
                <td onClick={e => { e.stopPropagation(); store.toggleHostSelection(host.id); }}>
                  <input
                    type="checkbox"
                    checked={state.selectedHostIds.has(host.id)}
                    onChange={() => store.toggleHostSelection(host.id)}
                    style={{ accentColor: 'var(--accent)' }}
                    aria-label={`Select host ${host.ip || host.ipv6}`}
                  />
                </td>
                <td style={{ textAlign: 'center', padding: '6px 2px' }}>
                  {store.hostsWithNotes.has(host.id) && (
                    <span className="note-indicator-small" title="Has notes">{'\u270E'}</span>
                  )}
                </td>
                {columns.map(col => {
                  if (col.field === 'status') {
                    return (
                      <td key={col.field}>
                        <span className={`state-badge state-${stateClass(host.status.state)}`}>
                          {host.status.state}
                        </span>
                      </td>
                    );
                  }
                  if (col.field === 'openPortCount') {
                    return <td key={col.field} style={{ color: 'var(--green)' }}>{host.openPortCount}</td>;
                  }
                  if (col.field === 'closedPortCount') {
                    return <td key={col.field} style={{ color: 'var(--red)' }}>{host.closedPortCount}</td>;
                  }
                  if (col.field === 'filteredPortCount') {
                    return <td key={col.field} style={{ color: 'var(--yellow)' }}>{host.filteredPortCount}</td>;
                  }
                  if (col.field === 'ip' || col.field === 'ipv6' || col.field === 'mac') {
                    return <td key={col.field} className="mono" style={col.field === 'mac' ? { fontSize: 11 } : undefined}>{getHostField(host, col.field)}</td>;
                  }
                  if (col.field === 'mainOS') {
                    return <td key={col.field} className="truncate" style={{ maxWidth: 200 }}>{host.mainOS || '-'}</td>;
                  }
                  return <td key={col.field}>{getHostField(host, col.field)}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
        {hasMore && (
          <div style={{ padding: '12px 16px', textAlign: 'center' }}>
            <button className="btn btn-sm" onClick={() => setPage(p => p + 1)}>
              Load more ({hosts.length - pagedHosts.length} remaining)
            </button>
          </div>
        )}
        {hosts.length === 0 && (
          <div className="empty-state" role="status">
            <div className="icon" aria-hidden="true">{'\u2316'}</div>
            <div>No hosts match your current filters</div>
          </div>
        )}
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          items={getContextMenuItems(contextMenu.host)}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
}
