import React, { useState, useMemo } from 'react';
import type { NmapScan, NmapHost } from '../types/nmap';
import type { AppStore } from '../store/appStore';
import { stateClass } from '../utils/helpers';

interface PortsViewProps {
  scan: NmapScan;
  hosts: NmapHost[];
  store: AppStore;
}

type PortSortField = 'port' | 'protocol' | 'state' | 'service' | 'product' | 'count';

export function PortsView({ scan, hosts, store }: PortsViewProps) {
  const [search, setSearch] = useState('');
  const [stateFilter, setStateFilter] = useState<string>('all');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<PortSortField>('port');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [expandedPort, setExpandedPort] = useState<string | null>(null);

  // Recompute port summaries from filtered hosts
  const portSummaries = useMemo(() => {
    const map = new Map<string, {
      port: number;
      protocol: string;
      state: string;
      service: string;
      product: string;
      version: string;
      count: number;
      hosts: { ip: string; id: string }[];
    }>();
    for (const host of hosts) {
      const hostAddr = host.ip || host.ipv6;
      for (const port of host.ports) {
        const key = `${port.portid}/${port.protocol}/${port.state.state}`;
        const existing = map.get(key);
        if (existing) {
          existing.count++;
          existing.hosts.push({ ip: hostAddr, id: host.id });
        } else {
          map.set(key, {
            port: port.portid,
            protocol: port.protocol,
            state: port.state.state,
            service: port.service?.name || '',
            product: port.service?.product || '',
            version: port.service?.version || '',
            count: 1,
            hosts: [{ ip: hostAddr, id: host.id }],
          });
        }
      }
    }
    return Array.from(map.values());
  }, [hosts]);

  // Get unique states and protocols for filter dropdowns
  const states = useMemo(() => [...new Set(portSummaries.map(p => p.state))].sort(), [portSummaries]);
  const protocols = useMemo(() => [...new Set(portSummaries.map(p => p.protocol))].sort(), [portSummaries]);

  // Filter
  const filtered = useMemo(() => {
    let result = portSummaries;
    if (stateFilter !== 'all') result = result.filter(p => p.state === stateFilter);
    if (protocolFilter !== 'all') result = result.filter(p => p.protocol === protocolFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(p =>
        String(p.port).includes(q) ||
        p.service.toLowerCase().includes(q) ||
        p.product.toLowerCase().includes(q) ||
        p.version.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q)
      );
    }
    return result;
  }, [portSummaries, stateFilter, protocolFilter, search]);

  // Sort
  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1;
      switch (sortField) {
        case 'port': return (a.port - b.port) * dir;
        case 'protocol': return a.protocol.localeCompare(b.protocol) * dir;
        case 'state': return a.state.localeCompare(b.state) * dir;
        case 'service': return a.service.localeCompare(b.service) * dir;
        case 'product': return a.product.localeCompare(b.product) * dir;
        case 'count': return (a.count - b.count) * dir;
        default: return 0;
      }
    });
  }, [filtered, sortField, sortDir]);

  const handleSort = (field: PortSortField) => {
    if (sortField === field) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const getSortIndicator = (field: PortSortField) => {
    if (sortField !== field) return '';
    return sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="toolbar">
        <div className="search-box" style={{ maxWidth: 300 }}>
          <span className="icon">{'\u2315'}</span>
          <input
            className="input"
            type="text"
            placeholder="Search ports, services..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ paddingLeft: 28 }}
          />
        </div>
        <select className="select" value={stateFilter} onChange={e => setStateFilter(e.target.value)}>
          <option value="all">All States</option>
          {states.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="select" value={protocolFilter} onChange={e => setProtocolFilter(e.target.value)}>
          <option value="all">All Protocols</option>
          {protocols.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <span className="result-count">{sorted.length} port entries</span>
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('port')}>Port{getSortIndicator('port')}</th>
              <th onClick={() => handleSort('protocol')}>Protocol{getSortIndicator('protocol')}</th>
              <th onClick={() => handleSort('state')}>State{getSortIndicator('state')}</th>
              <th onClick={() => handleSort('service')}>Service{getSortIndicator('service')}</th>
              <th onClick={() => handleSort('product')}>Product{getSortIndicator('product')}</th>
              <th>Version</th>
              <th onClick={() => handleSort('count')}>Hosts{getSortIndicator('count')}</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(p => {
              const key = `${p.port}/${p.protocol}/${p.state}`;
              const isExpanded = expandedPort === key;
              return (
                <React.Fragment key={key}>
                  <tr
                    className="clickable"
                    onClick={() => setExpandedPort(isExpanded ? null : key)}
                  >
                    <td className="mono">{p.port}</td>
                    <td>{p.protocol}</td>
                    <td><span className={`state-badge state-${stateClass(p.state)}`}>{p.state}</span></td>
                    <td>{p.service || '-'}</td>
                    <td>{p.product || '-'}</td>
                    <td>{p.version || '-'}</td>
                    <td>
                      <span className="tag tag-blue">{p.count}</span>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={7} style={{ background: 'var(--bg-tertiary)', padding: '8px 16px' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                          Hosts with this port ({p.hosts.length}):
                        </div>
                        <div className="port-grid">
                          {p.hosts.map((h, i) => (
                            <span
                              key={i}
                              className="port-chip mono clickable"
                              style={{
                                background: 'var(--bg-primary)',
                                color: 'var(--accent)',
                                border: '1px solid var(--border-color)',
                                cursor: 'pointer',
                              }}
                              onClick={(e) => {
                                e.stopPropagation();
                                store.setSelectedHostId(h.id);
                                store.setViewMode('hosts');
                              }}
                              title={`View ${h.ip} in Hosts`}
                            >
                              {h.ip}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
        {sorted.length === 0 && (
          <div className="empty-state">
            <div className="icon">{'\u25C8'}</div>
            <div>No ports match your current filters</div>
          </div>
        )}
      </div>
    </div>
  );
}
