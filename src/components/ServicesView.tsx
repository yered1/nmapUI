import React, { useState, useMemo } from 'react';
import type { NmapScan, NmapHost } from '../types/nmap';
import type { AppStore } from '../store/appStore';

interface ServicesViewProps {
  scan: NmapScan;
  hosts: NmapHost[];
  store: AppStore;
}

type SvcSortField = 'name' | 'product' | 'version' | 'count' | 'ports';

export function ServicesView({ scan, hosts, store }: ServicesViewProps) {
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<SvcSortField>('count');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [expandedService, setExpandedService] = useState<string | null>(null);

  // Recompute service summaries from filtered hosts
  const serviceSummaries = useMemo(() => {
    const map = new Map<string, {
      name: string;
      product: string;
      version: string;
      extrainfo: string;
      tunnel: string;
      count: number;
      ports: number[];
      hosts: { ip: string; id: string; port: number; protocol: string }[];
      cpes: string[];
    }>();
    for (const host of hosts) {
      for (const port of host.ports) {
        if (!port.service?.name) continue;
        const key = `${port.service.name}/${port.service.product || ''}/${port.service.version || ''}`;
        const existing = map.get(key);
        const hostAddr = host.ip || host.ipv6;
        if (existing) {
          existing.count++;
          if (!existing.ports.includes(port.portid)) existing.ports.push(port.portid);
          existing.hosts.push({ ip: hostAddr, id: host.id, port: port.portid, protocol: port.protocol });
          if (port.service.cpes) {
            for (const cpe of port.service.cpes) {
              if (!existing.cpes.includes(cpe)) existing.cpes.push(cpe);
            }
          }
        } else {
          map.set(key, {
            name: port.service.name,
            product: port.service.product || '',
            version: port.service.version || '',
            extrainfo: port.service.extrainfo || '',
            tunnel: port.service.tunnel || '',
            count: 1,
            ports: [port.portid],
            hosts: [{ ip: hostAddr, id: host.id, port: port.portid, protocol: port.protocol }],
            cpes: port.service.cpes ? [...port.service.cpes] : [],
          });
        }
      }
    }
    return Array.from(map.values());
  }, [hosts]);

  // Filter
  const filtered = useMemo(() => {
    if (!search) return serviceSummaries;
    const q = search.toLowerCase();
    return serviceSummaries.filter(s =>
      s.name.toLowerCase().includes(q) ||
      s.product.toLowerCase().includes(q) ||
      s.version.toLowerCase().includes(q) ||
      s.extrainfo.toLowerCase().includes(q) ||
      s.cpes.some(c => c.toLowerCase().includes(q))
    );
  }, [serviceSummaries, search]);

  // Sort
  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1;
      switch (sortField) {
        case 'name': return a.name.localeCompare(b.name) * dir;
        case 'product': return a.product.localeCompare(b.product) * dir;
        case 'version': return a.version.localeCompare(b.version) * dir;
        case 'count': return (a.count - b.count) * dir;
        case 'ports': return (a.ports.length - b.ports.length) * dir;
        default: return 0;
      }
    });
  }, [filtered, sortField, sortDir]);

  const handleSort = (field: SvcSortField) => {
    if (sortField === field) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir(field === 'count' ? 'desc' : 'asc');
    }
  };

  const getSortIndicator = (field: SvcSortField) => {
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
            placeholder="Search services, products, CPEs..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ paddingLeft: 28 }}
          />
        </div>
        <span className="result-count">{sorted.length} services</span>
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('name')}>Service{getSortIndicator('name')}</th>
              <th onClick={() => handleSort('product')}>Product{getSortIndicator('product')}</th>
              <th onClick={() => handleSort('version')}>Version{getSortIndicator('version')}</th>
              <th>Extra Info</th>
              <th>Tunnel</th>
              <th onClick={() => handleSort('ports')}>Ports{getSortIndicator('ports')}</th>
              <th onClick={() => handleSort('count')}>Instances{getSortIndicator('count')}</th>
              <th>CPEs</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((svc, idx) => {
              const key = `${svc.name}/${svc.product}/${svc.version}`;
              const isExpanded = expandedService === key;
              return (
                <React.Fragment key={key + idx}>
                  <tr
                    className="clickable"
                    onClick={() => setExpandedService(isExpanded ? null : key)}
                  >
                    <td style={{ fontWeight: 600 }}>{svc.name}</td>
                    <td>{svc.product || '-'}</td>
                    <td className="mono">{svc.version || '-'}</td>
                    <td className="truncate" style={{ maxWidth: 150 }}>{svc.extrainfo || '-'}</td>
                    <td>{svc.tunnel || '-'}</td>
                    <td>
                      <div className="port-grid">
                        {svc.ports.slice(0, 5).map(p => (
                          <span key={p} className="port-chip mono" style={{ background: 'var(--green-dim)', color: 'var(--green)' }}>{p}</span>
                        ))}
                        {svc.ports.length > 5 && (
                          <span className="port-chip" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                            +{svc.ports.length - 5}
                          </span>
                        )}
                      </div>
                    </td>
                    <td><span className="tag tag-purple">{svc.count}</span></td>
                    <td className="mono truncate" style={{ fontSize: 10, maxWidth: 200 }}>
                      {svc.cpes.join(', ') || '-'}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={8} style={{ background: 'var(--bg-tertiary)', padding: '8px 16px' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                          Host instances ({svc.hosts.length}):
                        </div>
                        <table className="data-table" style={{ background: 'var(--bg-primary)' }}>
                          <thead>
                            <tr>
                              <th>Host IP</th>
                              <th>Port</th>
                              <th>Protocol</th>
                            </tr>
                          </thead>
                          <tbody>
                            {svc.hosts.map((h, i) => (
                              <tr key={i}>
                                <td
                                  className="mono clickable"
                                  style={{ color: 'var(--accent)', cursor: 'pointer' }}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    store.setSelectedHostId(h.id);
                                    store.setViewMode('hosts');
                                  }}
                                  title={`View ${h.ip} in Hosts`}
                                >
                                  {h.ip}
                                </td>
                                <td className="mono">{h.port}</td>
                                <td>{h.protocol}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {svc.cpes.length > 0 && (
                          <div style={{ marginTop: 8 }}>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>CPEs:</div>
                            {svc.cpes.map((cpe, i) => (
                              <div key={i} className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>{cpe}</div>
                            ))}
                          </div>
                        )}
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
            <div className="icon">{'\u2699'}</div>
            <div>No services match your current search</div>
          </div>
        )}
      </div>
    </div>
  );
}
