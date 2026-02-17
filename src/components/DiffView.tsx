import React, { useState, useCallback, useMemo } from 'react';
import type { NmapScan, NmapHost } from '../types/nmap';
import { parseNmapOutput } from '../parser/nmapParser';
import { stateClass } from '../utils/helpers';

interface DiffViewProps {
  baseScan: NmapScan;
  onClose: () => void;
}

interface HostDiff {
  ip: string;
  hostname: string;
  status: 'added' | 'removed' | 'changed' | 'unchanged';
  baseHost: NmapHost | null;
  compareHost: NmapHost | null;
  portChanges: PortDiff[];
}

interface PortDiff {
  port: number;
  protocol: string;
  status: 'added' | 'removed' | 'changed' | 'unchanged';
  baseState?: string;
  compareState?: string;
  baseService?: string;
  compareService?: string;
}

export function DiffView({ baseScan, onClose }: DiffViewProps) {
  const [compareScan, setCompareScan] = useState<NmapScan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const handleFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string;
        const scan = parseNmapOutput(content);
        setCompareScan(scan);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to parse comparison file');
      }
    };
    reader.readAsText(file);
  }, []);

  const diffs = useMemo<HostDiff[]>(() => {
    if (!compareScan) return [];

    const baseMap = new Map<string, NmapHost>();
    for (const h of baseScan.hosts) {
      baseMap.set(h.ip || h.ipv6, h);
    }

    const compareMap = new Map<string, NmapHost>();
    for (const h of compareScan.hosts) {
      compareMap.set(h.ip || h.ipv6, h);
    }

    const allIPs = new Set([...baseMap.keys(), ...compareMap.keys()]);
    const results: HostDiff[] = [];

    for (const ip of allIPs) {
      const baseHost = baseMap.get(ip) || null;
      const compareHost = compareMap.get(ip) || null;

      const portChanges: PortDiff[] = [];
      const allPorts = new Set<string>();

      if (baseHost) {
        for (const p of baseHost.ports) allPorts.add(`${p.portid}/${p.protocol}`);
      }
      if (compareHost) {
        for (const p of compareHost.ports) allPorts.add(`${p.portid}/${p.protocol}`);
      }

      for (const portKey of allPorts) {
        const [portStr, proto] = portKey.split('/');
        const portNum = Number(portStr);
        const basePort = baseHost?.ports.find(p => p.portid === portNum && p.protocol === proto);
        const comparePort = compareHost?.ports.find(p => p.portid === portNum && p.protocol === proto);

        if (basePort && !comparePort) {
          portChanges.push({ port: portNum, protocol: proto, status: 'removed', baseState: basePort.state.state, baseService: basePort.service?.name });
        } else if (!basePort && comparePort) {
          portChanges.push({ port: portNum, protocol: proto, status: 'added', compareState: comparePort.state.state, compareService: comparePort.service?.name });
        } else if (basePort && comparePort) {
          const stateChanged = basePort.state.state !== comparePort.state.state;
          const serviceChanged = basePort.service?.name !== comparePort.service?.name;
          portChanges.push({
            port: portNum, protocol: proto,
            status: stateChanged || serviceChanged ? 'changed' : 'unchanged',
            baseState: basePort.state.state, compareState: comparePort.state.state,
            baseService: basePort.service?.name, compareService: comparePort.service?.name,
          });
        }
      }

      let status: HostDiff['status'];
      if (!baseHost) status = 'added';
      else if (!compareHost) status = 'removed';
      else if (portChanges.some(pc => pc.status !== 'unchanged') || baseHost.status.state !== compareHost.status.state) status = 'changed';
      else status = 'unchanged';

      results.push({
        ip,
        hostname: (compareHost || baseHost)?.hostname || '',
        status,
        baseHost,
        compareHost,
        portChanges: portChanges.filter(pc => pc.status !== 'unchanged'),
      });
    }

    return results.sort((a, b) => {
      const order = { added: 0, removed: 1, changed: 2, unchanged: 3 };
      return order[a.status] - order[b.status];
    });
  }, [baseScan, compareScan]);

  const stats = useMemo(() => {
    return {
      added: diffs.filter(d => d.status === 'added').length,
      removed: diffs.filter(d => d.status === 'removed').length,
      changed: diffs.filter(d => d.status === 'changed').length,
      unchanged: diffs.filter(d => d.status === 'unchanged').length,
    };
  }, [diffs]);

  if (!compareScan) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 500 }}>
          <div className="modal-header">
            <span className="modal-title">Compare Scans</span>
            <button className="btn btn-sm btn-ghost btn-icon" onClick={onClose} aria-label="Close">{'\u2715'}</button>
          </div>
          <div className="modal-body" style={{ textAlign: 'center' }}>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 16, fontSize: 13 }}>
              Drop a second scan file to compare against the current scan.
            </p>
            {error && <div className="error-banner" style={{ marginBottom: 12 }}>{error}</div>}
            <div
              className={`drop-area ${dragOver ? 'drag-over' : ''}`}
              style={{ padding: 40 }}
              onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onClick={() => {
                const input = document.createElement('input');
                input.type = 'file';
                input.accept = '.xml,.gnmap,.nmap,.txt';
                input.onchange = () => { const f = input.files?.[0]; if (f) handleFile(f); };
                input.click();
              }}
            >
              <div style={{ fontSize: 32, opacity: 0.4, marginBottom: 8 }}>{'\u2194'}</div>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Drop comparison scan file</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>or click to browse</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const changedDiffs = diffs.filter(d => d.status !== 'unchanged');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 800, maxHeight: '85vh' }}>
        <div className="modal-header">
          <span className="modal-title">Scan Comparison</span>
          <button className="btn btn-sm btn-ghost btn-icon" onClick={onClose} aria-label="Close">{'\u2715'}</button>
        </div>
        <div className="modal-body" style={{ maxHeight: '65vh', overflow: 'auto' }}>
          {/* Summary */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
            <span className="tag tag-green">+{stats.added} new</span>
            <span className="tag tag-red">-{stats.removed} removed</span>
            <span className="tag tag-yellow">~{stats.changed} changed</span>
            <span className="tag" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
              {stats.unchanged} unchanged
            </span>
          </div>

          {changedDiffs.length === 0 ? (
            <div className="empty-state"><div>No differences found between the two scans</div></div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Host</th>
                  <th>Port Changes</th>
                </tr>
              </thead>
              <tbody>
                {changedDiffs.map(diff => (
                  <tr key={diff.ip}>
                    <td>
                      <span className={`tag ${
                        diff.status === 'added' ? 'tag-green' :
                        diff.status === 'removed' ? 'tag-red' : 'tag-yellow'
                      }`}>
                        {diff.status === 'added' ? '+' : diff.status === 'removed' ? '-' : '~'} {diff.status}
                      </span>
                    </td>
                    <td className="mono">{diff.ip}{diff.hostname ? ` (${diff.hostname})` : ''}</td>
                    <td>
                      {diff.portChanges.length === 0 ? (
                        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                          {diff.status === 'added' ? `${diff.compareHost?.openPortCount || 0} open ports` :
                           diff.status === 'removed' ? `was: ${diff.baseHost?.openPortCount || 0} open ports` :
                           'host status changed'}
                        </span>
                      ) : (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                          {diff.portChanges.slice(0, 8).map(pc => (
                            <span key={`${pc.port}/${pc.protocol}`} className="mono" style={{
                              fontSize: 10,
                              padding: '1px 5px',
                              borderRadius: 3,
                              background: pc.status === 'added' ? 'var(--green-dim)' :
                                pc.status === 'removed' ? 'var(--red-dim)' : 'var(--yellow-dim)',
                              color: pc.status === 'added' ? 'var(--green)' :
                                pc.status === 'removed' ? 'var(--red)' : 'var(--yellow)',
                            }}>
                              {pc.status === 'added' ? '+' : pc.status === 'removed' ? '-' : '~'}
                              {pc.port}/{pc.protocol}
                              {pc.status === 'changed' ? ` (${pc.baseState}\u2192${pc.compareState})` : ''}
                            </span>
                          ))}
                          {diff.portChanges.length > 8 && (
                            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                              +{diff.portChanges.length - 8} more
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={() => setCompareScan(null)}>Load Different Scan</button>
          <button className="btn btn-primary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
