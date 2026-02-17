import React from 'react';
import type { NmapScan, ViewMode } from '../types/nmap';

interface SidebarProps {
  viewMode: ViewMode;
  onViewChange: (mode: ViewMode) => void;
  scan: NmapScan;
  filteredCount: number;
  noteCount: number;
}

export function Sidebar({ viewMode, onViewChange, scan, filteredCount, noteCount }: SidebarProps) {
  const navItems: { mode: ViewMode; icon: string; label: string; badge?: string | number }[] = [
    { mode: 'dashboard', icon: '\u25A6', label: 'Dashboard' },
    { mode: 'hosts', icon: '\u2316', label: 'Hosts', badge: filteredCount },
    { mode: 'ports', icon: '\u25C8', label: 'Ports', badge: scan.uniquePorts.length },
    { mode: 'services', icon: '\u2699', label: 'Services', badge: scan.uniqueServices.length },
    { mode: 'notes', icon: '\u270E', label: 'Notes', badge: noteCount || undefined },
  ];

  return (
    <nav className="app-sidebar" role="navigation" aria-label="Main navigation">
      <div className="sidebar-section">
        <div className="sidebar-section-title" id="views-heading">Views</div>
        <div role="list" aria-labelledby="views-heading">
          {navItems.map(item => (
            <div
              key={item.mode}
              role="listitem"
              className={`sidebar-item ${viewMode === item.mode ? 'active' : ''}`}
              onClick={() => onViewChange(item.mode)}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onViewChange(item.mode); }}
              tabIndex={0}
              aria-current={viewMode === item.mode ? 'page' : undefined}
              aria-label={`${item.label}${item.badge !== undefined ? ` (${item.badge})` : ''}`}
            >
              <span className="icon" aria-hidden="true">{item.icon}</span>
              <span>{item.label}</span>
              {item.badge !== undefined && <span className="badge" aria-hidden="true">{item.badge}</span>}
            </div>
          ))}
        </div>
      </div>

      <div className="sidebar-divider" role="separator" />

      <div className="sidebar-section">
        <div className="sidebar-section-title">Scan Info</div>
        <div style={{ padding: '4px 16px', fontSize: 11, color: 'var(--text-muted)' }}>
          <div>Nmap {scan.version}</div>
          <div>{scan.scaninfo.map(si => si.type).join(', ') || 'N/A'}</div>
          <div>{scan.scanDuration}s duration</div>
          <div>{scan.hostsUp} up / {scan.hostsDown} down</div>
        </div>
      </div>

      <div className="header-spacer" />

      <div className="sidebar-section" style={{ padding: '8px 16px', borderTop: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          Shortcuts: Ctrl+F Search, Ctrl+E Export, Ctrl+D Compare, Esc Back
        </div>
      </div>
    </nav>
  );
}
