import React, { useState } from 'react';
import type { NmapHost, HostDetailTab, Note } from '../types/nmap';
import type { AppStore } from '../store/appStore';
import { stateClass, formatUptime, copyToClipboard } from '../utils/helpers';
import { sanitizeNoteHtml } from '../utils/sanitize';
import { ScriptSuggestions } from './ScriptSuggestions';

interface HostDetailProps {
  host: NmapHost;
  onBack: () => void;
  store: AppStore;
  onImportResults?: () => void;
}

export function HostDetail({ host, onBack, store, onImportResults }: HostDetailProps) {
  const [activeTab, setActiveTab] = useState<HostDetailTab>('ports');
  const [expandedScripts, setExpandedScripts] = useState<Set<string>>(new Set());
  const [screenshotPreview, setScreenshotPreview] = useState<string | null>(null);

  const hostNotes = store.getNotesForHost(host.id);

  const toggleScript = (key: string) => {
    setExpandedScripts(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const tabs: { id: HostDetailTab; label: string; count?: number; highlight?: boolean }[] = [
    { id: 'ports', label: 'Ports', count: host.ports.length },
    { id: 'os', label: 'OS Detection', count: host.os.osmatch.length },
    { id: 'scripts', label: 'Scripts', count: host.hostscripts.length + host.ports.reduce((s, p) => s + p.scripts.length, 0) },
    { id: 'notes', label: 'Notes', count: hostNotes.length, highlight: hostNotes.length > 0 },
    { id: 'suggestions', label: 'Script Suggestions' },
    { id: 'trace', label: 'Trace & Timing' },
    { id: 'raw', label: 'All Data' },
  ];

  return (
    <div className="host-detail">
      {/* Header */}
      <div className="host-detail-header">
        <button className="back-btn" onClick={onBack}>
          {'\u2190'} Back to hosts
        </button>
        <div className="host-detail-title">
          <span className="mono">{host.ip || host.ipv6 || 'N/A'}</span>
          {host.hostname && (
            <span style={{ fontWeight: 400, fontSize: 14, color: 'var(--text-secondary)' }}>
              ({host.hostname})
            </span>
          )}
          <span className={`state-badge state-${stateClass(host.status.state)}`}>{host.status.state}</span>
          {store.hostsWithNotes.has(host.id) && (
            <span className="note-indicator" title="Has notes">
              {'\u270E'}
            </span>
          )}
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => copyToClipboard(host.ip || host.ipv6)}
            title="Copy IP"
            aria-label="Copy IP address"
          >
            Copy IP
          </button>
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => store.openNoteEditor({ hostId: host.id, ip: host.ip || host.ipv6 })}
            title="Add note for this host"
            aria-label="Add note"
          >
            + Note
          </button>
        </div>
        <div className="host-detail-meta">
          {host.mac && (
            <span>
              <span className="label">MAC:</span> {host.mac}
              {host.addresses.find(a => a.addrtype === 'mac')?.vendor &&
                ` (${host.addresses.find(a => a.addrtype === 'mac')!.vendor})`
              }
            </span>
          )}
          {host.mainOS && <span><span className="label">OS:</span> {host.mainOS}</span>}
          <span><span className="label">Open:</span> {host.openPortCount}</span>
          <span><span className="label">Closed:</span> {host.closedPortCount}</span>
          <span><span className="label">Filtered:</span> {host.filteredPortCount}</span>
          {host.distance !== null && <span><span className="label">Distance:</span> {host.distance} hops</span>}
          {host.uptime && <span><span className="label">Uptime:</span> {formatUptime(host.uptime.seconds)}</span>}
          <span><span className="label">Reason:</span> {host.status.reason}</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="host-detail-tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''} ${tab.highlight ? 'tab-highlight' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label} {tab.count !== undefined && tab.count > 0 && `(${tab.count})`}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="host-detail-body">
        {activeTab === 'ports' && (
          <PortsTab host={host} store={store} expandedScripts={expandedScripts} toggleScript={toggleScript} />
        )}
        {activeTab === 'os' && <OSTab host={host} />}
        {activeTab === 'scripts' && (
          <ScriptsTab host={host} expandedScripts={expandedScripts} toggleScript={toggleScript} />
        )}
        {activeTab === 'notes' && (
          <NotesTab host={host} notes={hostNotes} store={store} onPreviewScreenshot={setScreenshotPreview} />
        )}
        {activeTab === 'suggestions' && (
          <ScriptSuggestions host={host} onImportResults={onImportResults} />
        )}
        {activeTab === 'trace' && <TraceTab host={host} />}
        {activeTab === 'raw' && <RawTab host={host} />}
      </div>

      {/* Screenshot preview overlay */}
      {screenshotPreview && screenshotPreview.startsWith('data:image/') && (
        <div className="screenshot-preview-overlay" onClick={() => setScreenshotPreview(null)}>
          <img src={screenshotPreview} alt="Screenshot preview" />
          <button className="btn btn-sm screenshot-preview-close" onClick={() => setScreenshotPreview(null)}>
            Close
          </button>
        </div>
      )}
    </div>
  );
}

function PortsTab({ host, store, expandedScripts, toggleScript }: {
  host: NmapHost;
  store: AppStore;
  expandedScripts: Set<string>;
  toggleScript: (key: string) => void;
}) {
  if (host.ports.length === 0) {
    return <div className="empty-state"><div>No port data available</div></div>;
  }

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th style={{ width: 24 }}></th>
          <th>Port</th>
          <th>State</th>
          <th>Service</th>
          <th>Product</th>
          <th>Version</th>
          <th>Extra Info</th>
          <th>Confidence</th>
          <th>CPEs</th>
        </tr>
      </thead>
      <tbody>
        {host.ports.map(port => {
          const portKey = `${host.id}:${port.portid}/${port.protocol}`;
          const hasNotes = store.portsWithNotes.has(portKey);
          return (
            <React.Fragment key={`${port.portid}/${port.protocol}`}>
              <tr>
                <td style={{ textAlign: 'center', padding: '6px 4px' }}>
                  {hasNotes && (
                    <span className="note-indicator-small" title="Has notes">
                      {'\u270E'}
                    </span>
                  )}
                </td>
                <td className="mono">
                  {port.portid}/{port.protocol}
                  <button
                    className="btn-inline-note"
                    onClick={e => {
                      e.stopPropagation();
                      store.openNoteEditor({
                        hostId: host.id,
                        ip: host.ip || host.ipv6,
                        portId: port.portid,
                        protocol: port.protocol,
                      });
                    }}
                    title="Add note for this port"
                  >
                    +
                  </button>
                </td>
                <td>
                  <span className={`state-badge state-${stateClass(port.state.state)}`}>
                    {port.state.state}
                  </span>
                </td>
                <td>{port.service?.name || '-'}</td>
                <td>{port.service?.product || '-'}</td>
                <td>{port.service?.version || '-'}</td>
                <td className="truncate" style={{ maxWidth: 180 }}>
                  {port.service?.extrainfo || '-'}
                  {port.service?.tunnel ? ` [${port.service.tunnel}]` : ''}
                </td>
                <td>{port.service ? `${port.service.conf}/10` : '-'}</td>
                <td className="mono" style={{ fontSize: 10 }}>
                  {port.service?.cpes.join(', ') || '-'}
                </td>
              </tr>
              {port.scripts.map(script => {
                const key = `${port.portid}-${script.id}`;
                const isExpanded = expandedScripts.has(key);
                return (
                  <tr key={key}>
                    <td colSpan={9} style={{ padding: 0 }}>
                      <div className="script-block" style={{ margin: '2px 8px' }}>
                        <div className="script-header" onClick={() => toggleScript(key)}>
                          {isExpanded ? '\u25BC' : '\u25B6'} {script.id}
                        </div>
                        {isExpanded && <div className="script-output">{script.output}</div>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </React.Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

function NotesTab({ host, notes, store, onPreviewScreenshot }: {
  host: NmapHost;
  notes: Note[];
  store: AppStore;
  onPreviewScreenshot: (url: string) => void;
}) {
  if (notes.length === 0) {
    return (
      <div className="empty-state">
        <div className="icon">{'\u270E'}</div>
        <div>No notes for this host yet</div>
        <button
          className="btn btn-sm btn-primary"
          style={{ marginTop: 12 }}
          onClick={() => store.openNoteEditor({ hostId: host.id, ip: host.ip || host.ipv6 })}
        >
          Add a note
        </button>
      </div>
    );
  }

  const formatDate = (ts: number) => new Date(ts).toLocaleString();

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <button
          className="btn btn-sm btn-primary"
          onClick={() => store.openNoteEditor({ hostId: host.id, ip: host.ip || host.ipv6 })}
        >
          + New Note
        </button>
      </div>
      {notes.map(note => (
        <div key={note.id} className="note-card" style={{ marginBottom: 12 }}>
          <div className="note-card-header">
            <div className="note-card-title-area">
              <span className="note-card-title">{note.title}</span>
              <div className="note-card-meta">
                <span>{formatDate(note.updatedAt)}</span>
              </div>
            </div>
            <div className="note-card-actions">
              <button className="btn btn-sm btn-ghost" onClick={() => store.editNote(note.id)}>
                Edit
              </button>
              <button
                className="btn btn-sm btn-ghost btn-danger"
                onClick={() => {
                  if (confirm('Delete this note?')) store.deleteNote(note.id);
                }}
              >
                Delete
              </button>
            </div>
          </div>
          <div className="note-card-body">
            {note.targets.some(t => t.portId !== undefined) && (
              <div className="note-targets-section">
                <div className="note-section-label">Ports</div>
                <div className="target-chips">
                  {note.targets.filter(t => t.portId !== undefined).map((t, i) => (
                    <span key={i} className="target-chip">
                      {t.portId}/{t.protocol}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {note.content && (
              <div className="note-content-section">
                {note.content.trim().startsWith('<') ? (
                  <div
                    className="note-content-html"
                    dangerouslySetInnerHTML={{ __html: sanitizeNoteHtml(note.content) }}
                  />
                ) : (
                  <div className="note-content-text">{note.content}</div>
                )}
              </div>
            )}
            {note.screenshots.length > 0 && (
              <div className="note-screenshots-section">
                <div className="screenshot-grid">
                  {note.screenshots.filter(ss => ss.dataUrl.startsWith('data:image/')).map(ss => (
                    <div
                      key={ss.id}
                      className="screenshot-thumb"
                      onClick={() => onPreviewScreenshot(ss.dataUrl)}
                    >
                      <img src={ss.dataUrl} alt={ss.fileName} />
                      <div className="screenshot-name">{ss.fileName}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function OSTab({ host }: { host: NmapHost }) {
  if (host.os.osmatch.length === 0 && host.os.osfingerprint.length === 0) {
    return <div className="empty-state"><div>No OS detection data available</div></div>;
  }

  return (
    <div>
      {host.os.portused.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div className="section-title">Ports Used for Detection</div>
          <div className="port-grid">
            {host.os.portused.map((pu, i) => (
              <span key={i} className={`port-chip state-${stateClass(pu.state)}`}>
                {pu.portid}/{pu.proto} ({pu.state})
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="section-title">OS Matches</div>
      {host.os.osmatch.map((om, i) => (
        <div key={i} className="card" style={{ marginBottom: 8 }}>
          <div className="card-header">
            <span style={{ flex: 1 }}>{om.name}</span>
            <span className="tag tag-blue">{om.accuracy}% accuracy</span>
          </div>
          <div className="card-body">
            {om.osclass.length > 0 && (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Vendor</th>
                    <th>Family</th>
                    <th>Generation</th>
                    <th>Type</th>
                    <th>Accuracy</th>
                    <th>CPEs</th>
                  </tr>
                </thead>
                <tbody>
                  {om.osclass.map((oc, j) => (
                    <tr key={j}>
                      <td>{oc.vendor || '-'}</td>
                      <td>{oc.osfamily || '-'}</td>
                      <td>{oc.osgen || '-'}</td>
                      <td>{oc.type || '-'}</td>
                      <td>{oc.accuracy}%</td>
                      <td className="mono" style={{ fontSize: 10 }}>{oc.cpes.join(', ') || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      ))}

      {host.os.osfingerprint.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div className="section-title">OS Fingerprint</div>
          {host.os.osfingerprint.map((fp, i) => (
            <div key={i} className="script-output">{fp}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function ScriptsTab({ host, expandedScripts, toggleScript }: {
  host: NmapHost;
  expandedScripts: Set<string>;
  toggleScript: (key: string) => void;
}) {
  const allScripts: { source: string; id: string; output: string }[] = [];

  for (const script of host.hostscripts) {
    allScripts.push({ source: 'host', id: script.id, output: script.output });
  }
  for (const port of host.ports) {
    for (const script of port.scripts) {
      allScripts.push({
        source: `${port.portid}/${port.protocol}`,
        id: script.id,
        output: script.output,
      });
    }
  }

  if (allScripts.length === 0) {
    return <div className="empty-state"><div>No script output available</div></div>;
  }

  return (
    <div>
      {allScripts.map((script, i) => {
        const key = `scripts-${i}-${script.id}`;
        const isExpanded = expandedScripts.has(key);
        return (
          <div key={key} className="script-block">
            <div className="script-header" onClick={() => toggleScript(key)}>
              {isExpanded ? '\u25BC' : '\u25B6'} {script.id}
              <span style={{ float: 'right', color: 'var(--text-muted)', fontWeight: 400, fontSize: 11 }}>
                {script.source}
              </span>
            </div>
            {isExpanded && <div className="script-output">{script.output}</div>}
          </div>
        );
      })}
    </div>
  );
}

function TraceTab({ host }: { host: NmapHost }) {
  return (
    <div>
      <div className="section-title">Network Information</div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-body">
          <div className="info-grid">
            <span className="label">Distance</span>
            <span className="value">{host.distance !== null ? `${host.distance} hops` : 'N/A'}</span>
            <span className="label">Uptime</span>
            <span className="value">{host.uptime ? formatUptime(host.uptime.seconds) : 'N/A'}</span>
            <span className="label">Last Boot</span>
            <span className="value">{host.uptime?.lastboot || 'N/A'}</span>
          </div>
        </div>
      </div>

      {host.tcpsequence && (
        <>
          <div className="section-title">TCP Sequence Prediction</div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-body">
              <div className="info-grid">
                <span className="label">Index</span>
                <span className="value">{host.tcpsequence.index}</span>
                <span className="label">Difficulty</span>
                <span className="value">{host.tcpsequence.difficulty}</span>
                <span className="label">Values</span>
                <span className="value mono" style={{ fontSize: 11 }}>{host.tcpsequence.values}</span>
              </div>
            </div>
          </div>
        </>
      )}

      {host.ipidsequence && (
        <>
          <div className="section-title">IP ID Sequence</div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-body">
              <div className="info-grid">
                <span className="label">Class</span>
                <span className="value">{host.ipidsequence.class}</span>
                <span className="label">Values</span>
                <span className="value mono" style={{ fontSize: 11 }}>{host.ipidsequence.values}</span>
              </div>
            </div>
          </div>
        </>
      )}

      {host.tcptssequence && (
        <>
          <div className="section-title">TCP Timestamp Sequence</div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-body">
              <div className="info-grid">
                <span className="label">Class</span>
                <span className="value">{host.tcptssequence.class}</span>
                <span className="label">Values</span>
                <span className="value mono" style={{ fontSize: 11 }}>{host.tcptssequence.values}</span>
              </div>
            </div>
          </div>
        </>
      )}

      {host.times && (
        <>
          <div className="section-title">Timing</div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-body">
              <div className="info-grid">
                <span className="label">SRTT</span>
                <span className="value">{host.times.srtt} {'\u00B5'}s</span>
                <span className="label">RTT Variance</span>
                <span className="value">{host.times.rttvar} {'\u00B5'}s</span>
                <span className="label">Timeout</span>
                <span className="value">{host.times.to} {'\u00B5'}s</span>
              </div>
            </div>
          </div>
        </>
      )}

      {host.trace && host.trace.hops.length > 0 && (
        <>
          <div className="section-title">Traceroute (port {host.trace.port}/{host.trace.proto})</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>TTL</th>
                <th>RTT (ms)</th>
                <th>IP Address</th>
                <th>Hostname</th>
              </tr>
            </thead>
            <tbody>
              {host.trace.hops.map((hop, i) => (
                <tr key={i}>
                  <td>{hop.ttl}</td>
                  <td>{hop.rtt}</td>
                  <td className="mono">{hop.ipaddr}</td>
                  <td>{hop.host || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {!host.trace && !host.tcpsequence && !host.times && host.distance === null && (
        <div className="empty-state"><div>No trace or timing data available</div></div>
      )}
    </div>
  );
}

function RawTab({ host }: { host: NmapHost }) {
  return (
    <div>
      <div className="section-title">Complete Host Data</div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-header">Addresses ({host.addresses.length})</div>
        <div className="card-body">
          <table className="data-table">
            <thead><tr><th>Address</th><th>Type</th><th>Vendor</th></tr></thead>
            <tbody>
              {host.addresses.map((addr, i) => (
                <tr key={i}>
                  <td className="mono">{addr.addr}</td>
                  <td>{addr.addrtype}</td>
                  <td>{addr.vendor || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {host.hostnames.length > 0 && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="card-header">Hostnames ({host.hostnames.length})</div>
          <div className="card-body">
            <table className="data-table">
              <thead><tr><th>Name</th><th>Type</th></tr></thead>
              <tbody>
                {host.hostnames.map((hn, i) => (
                  <tr key={i}><td>{hn.name}</td><td>{hn.type || '-'}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-header">Status</div>
        <div className="card-body">
          <div className="info-grid">
            <span className="label">State</span>
            <span className="value">{host.status.state}</span>
            <span className="label">Reason</span>
            <span className="value">{host.status.reason}</span>
            <span className="label">Reason TTL</span>
            <span className="value">{host.status.reason_ttl}</span>
            <span className="label">Start Time</span>
            <span className="value">{host.starttime ? new Date(host.starttime * 1000).toISOString() : 'N/A'}</span>
            <span className="label">End Time</span>
            <span className="value">{host.endtime ? new Date(host.endtime * 1000).toISOString() : 'N/A'}</span>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-header">Raw Port Data ({host.ports.length} ports)</div>
        <div className="card-body">
          <div className="script-output" style={{ maxHeight: 400 }}>
            {JSON.stringify(host.ports, null, 2)}
          </div>
        </div>
      </div>

      {host.smurfs.length > 0 && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="card-header">Smurf Information</div>
          <div className="card-body">
            {host.smurfs.map((s, i) => (
              <div key={i}>Responses: {s.responses}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
