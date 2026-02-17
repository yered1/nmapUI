import React from 'react';
import type { NmapScan, NmapHost } from '../types/nmap';
import type { AppStore } from '../store/appStore';
import { stateClass } from '../utils/helpers';

interface DashboardViewProps {
  scan: NmapScan;
  hosts: NmapHost[];
  store: AppStore;
}

export function DashboardView({ scan, hosts, store }: DashboardViewProps) {
  const openPorts = scan.uniquePorts.filter(p => p.state === 'open');
  const topServices = scan.uniqueServices.slice(0, 10);
  const topPorts = openPorts.slice(0, 10);
  const maxPortCount = Math.max(...topPorts.map(p => p.count), 1);
  const maxSvcCount = Math.max(...topServices.map(s => s.count), 1);

  // OS distribution
  const osMap = new Map<string, number>();
  for (const h of scan.hosts) {
    const os = h.os.osmatch[0]?.osclass[0]?.osfamily || 'Unknown';
    osMap.set(os, (osMap.get(os) || 0) + 1);
  }
  const osDistribution = Array.from(osMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const maxOsCount = Math.max(...osDistribution.map(([, c]) => c), 1);

  // Port state distribution
  const portStateMap = new Map<string, number>();
  for (const h of scan.hosts) {
    for (const p of h.ports) {
      portStateMap.set(p.state.state, (portStateMap.get(p.state.state) || 0) + 1);
    }
  }
  const portStates = Array.from(portStateMap.entries()).sort((a, b) => b[1] - a[1]);
  const totalPortInstances = portStates.reduce((sum, [, c]) => sum + c, 0);

  return (
    <div className="dashboard">
      <div className="dashboard-title">Scan Overview</div>
      <div className="dashboard-subtitle">
        {scan.args && <>Command: <code className="mono">{scan.args}</code> &mdash; </>}
        {scan.startstr}
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Hosts</div>
          <div className="stat-value stat-accent">{scan.totalHosts}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Hosts Up</div>
          <div className="stat-value stat-green">{scan.hostsUp}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Hosts Down</div>
          <div className="stat-value stat-red">{scan.hostsDown}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Open Ports</div>
          <div className="stat-value stat-cyan">{openPorts.length}</div>
          <div className="stat-detail">unique port/protocol combos</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Services</div>
          <div className="stat-value stat-purple">{scan.uniqueServices.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value stat-yellow">{scan.scanDuration}s</div>
        </div>
        {store.state.notes.length > 0 && (
          <div className="stat-card clickable" onClick={() => store.setViewMode('notes')}>
            <div className="stat-label">Notes</div>
            <div className="stat-value stat-orange">{store.state.notes.length}</div>
          </div>
        )}
      </div>

      <div className="dashboard-grid">
        {/* Top Open Ports */}
        <div className="card">
          <div className="card-header">Top Open Ports</div>
          <div className="card-body">
            {topPorts.length === 0 ? (
              <div className="empty-state"><div>No open ports found</div></div>
            ) : (
              <div className="bar-chart">
                {topPorts.map(p => (
                  <div key={`${p.port}/${p.protocol}`} className="bar-row">
                    <div className="bar-label mono">{p.port}/{p.protocol}</div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${(p.count / maxPortCount) * 100}%`,
                          background: 'var(--green)',
                        }}
                      />
                    </div>
                    <div className="bar-count">{p.count}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Top Services */}
        <div className="card">
          <div className="card-header">Top Services</div>
          <div className="card-body">
            {topServices.length === 0 ? (
              <div className="empty-state"><div>No services detected</div></div>
            ) : (
              <div className="bar-chart">
                {topServices.map(s => (
                  <div key={`${s.name}/${s.product}`} className="bar-row">
                    <div className="bar-label">{s.name}{s.product ? ` (${s.product})` : ''}</div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${(s.count / maxSvcCount) * 100}%`,
                          background: 'var(--purple)',
                        }}
                      />
                    </div>
                    <div className="bar-count">{s.count}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* OS Distribution */}
        <div className="card">
          <div className="card-header">OS Distribution</div>
          <div className="card-body">
            {osDistribution.length === 0 ? (
              <div className="empty-state"><div>No OS detection data</div></div>
            ) : (
              <div className="bar-chart">
                {osDistribution.map(([os, count]) => (
                  <div key={os} className="bar-row">
                    <div className="bar-label">{os}</div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${(count / maxOsCount) * 100}%`,
                          background: 'var(--accent)',
                        }}
                      />
                    </div>
                    <div className="bar-count">{count}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Port State Distribution */}
        <div className="card">
          <div className="card-header">Port States</div>
          <div className="card-body">
            {portStates.length === 0 ? (
              <div className="empty-state"><div>No port data</div></div>
            ) : (
              <div className="bar-chart">
                {portStates.map(([state, count]) => {
                  const color = state === 'open' ? 'var(--green)' :
                    state === 'closed' ? 'var(--red)' :
                    state === 'filtered' ? 'var(--yellow)' : 'var(--text-muted)';
                  return (
                    <div key={state} className="bar-row">
                      <div className="bar-label">{state}</div>
                      <div className="bar-track">
                        <div
                          className="bar-fill"
                          style={{
                            width: `${(count / totalPortInstances) * 100}%`,
                            background: color,
                          }}
                        />
                      </div>
                      <div className="bar-count">{count}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Scan Details */}
      <div className="section-title">Scan Details</div>
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-body">
          <div className="info-grid">
            <span className="label">Command</span>
            <code className="mono value">{scan.args || 'N/A'}</code>
            <span className="label">Scanner</span>
            <span className="value">{scan.scanner} {scan.version}</span>
            <span className="label">Start Time</span>
            <span className="value">{scan.startstr || 'N/A'}</span>
            <span className="label">Duration</span>
            <span className="value">{scan.scanDuration} seconds</span>
            <span className="label">Scan Types</span>
            <span className="value">{scan.scaninfo.map(si => `${si.type} (${si.protocol})`).join(', ') || 'N/A'}</span>
            <span className="label">Services Scanned</span>
            <span className="value">{scan.scaninfo.map(si => si.numservices).join(', ') || 'N/A'}</span>
            <span className="label">Verbosity</span>
            <span className="value">{scan.verbose}</span>
            <span className="label">Debug Level</span>
            <span className="value">{scan.debugging}</span>
            <span className="label">Exit Status</span>
            <span className="value">{scan.runstats.finished.exit || 'N/A'}</span>
            <span className="label">Summary</span>
            <span className="value">{scan.runstats.finished.summary || 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* Quick Host List */}
      <div className="section-title">Hosts ({hosts.length})</div>
      <div className="card">
        <div className="card-body" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Status</th>
                <th>Open Ports</th>
                <th>OS</th>
              </tr>
            </thead>
            <tbody>
              {hosts.slice(0, 20).map(host => (
                <tr
                  key={host.id}
                  className="clickable"
                  onClick={() => {
                    store.setViewMode('hosts');
                    store.setSelectedHostId(host.id);
                  }}
                >
                  <td className="mono">{host.ip || host.ipv6 || 'N/A'}</td>
                  <td>{host.hostname || '-'}</td>
                  <td><span className={`state-badge state-${stateClass(host.status.state)}`}>{host.status.state}</span></td>
                  <td>{host.openPortCount}</td>
                  <td className="truncate" style={{ maxWidth: 200 }}>{host.mainOS || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {hosts.length > 20 && (
            <div style={{ padding: '8px 16px', textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
              Showing 20 of {hosts.length} hosts.{' '}
              <span
                style={{ color: 'var(--accent)', cursor: 'pointer' }}
                onClick={() => store.setViewMode('hosts')}
              >
                View all →
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
